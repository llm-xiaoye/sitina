#!/usr/bin/env python3
"""Code Mode authority host.

This is deliberately an executable, not an importable Sitina authority API.
The parent CLI supplies one control FD and one one-shot bootstrap FD.  The
signing key is derived and retained only in this process; workers receive no
bootstrap or control descriptor.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import sys
import time
import stat
from pathlib import Path
from typing import Any, Mapping
import urllib.error
import urllib.request
from urllib.parse import urlparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

_SOURCE_ROOT = Path(__file__).resolve().parents[1]
STRUCTURED_RESPONSE_TOOL_NAME = "sitina_structured_response"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))
from sitina.cas.local import LocalCAS
from sitina.journal.local import LocalJournal
from sitina.journal.model import (
    canonical_json_bytes, parse_canonical_json, planned_operation_hash,
    proof_manifest_hash as canonical_proof_manifest_hash,
    acceptance_event_projection_hash, code_mode_gate_projection,
    payload_self_hash, code_mode_producer_spec,
    domain_hash,
    CODE_MODE_PRE_PROVIDER_AUTHORIZATION_SCHEMA, CODE_MODE_PRE_PROVIDER_PHASES,
    CODE_MODE_FAST_PRE_PROVIDER_PHASE,
    pre_provider_call_identity, provider_call_identity_v2,
    CODE_MODE_FORGE_CHILD_AUTHORIZATION_SCHEMA,
    CODE_MODE_FORGE_CHILD_AUTHORIZATION_EVENT_TYPE,
    CODE_MODE_FORGE_CHILD_AUTHORIZATION_PURPOSE,
    attempt_control_authorization_projection,
    CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_SCHEMA,
    CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_EVENT_TYPE,
    CODE_MODE_ATTEMPT_CONTROL_AUTHORIZATION_PURPOSE,
    forge_child_authorization_projection,
    CODE_MODE_ROOT_FSM_STAGES,
    execution_parent_hash,
    execution_parent_projection,
    CODE_MODE_EXECUTION_PARENT_SCHEMA,
    CODE_MODE_EXECUTION_PARENT_EVENT_TYPE,
    CODE_MODE_EXECUTION_PARENT_PURPOSE,
    CODE_MODE_LIVE_CAPABILITY_PURPOSES,
)
from sitina.protocols.terminal import BlockerKind
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider
from sitina.runners.provider import (
    ANTHROPIC_MESSAGES,
    OPENAI_CHAT_COMPLETIONS,
    ProviderError,
    infer_wire_protocol,
    provider_messages_for_wire,
    provider_tools_for_wire,
    provider_adapter_capabilities,
    provider_endpoint_allowed,
)
from sitina.runners.profiles import ProfileLoader
from sitina.security.macos_keychain import SecurityFrameworkKeychainBackend


def _canonical(value: object) -> bytes:
    return canonical_json_bytes(value)


def _hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _profile_wire_protocol(profile: Mapping[str, Any]) -> str:
    try:
        return infer_wire_protocol(
            str(profile.get("name") or ""),
            str(profile.get("base_url") or ""),
            str(profile.get("wire_protocol") or "") or None,
        )
    except Exception as error:
        raise AuthorityError("provider profile has no supported wire protocol") from error


def _profile_adapter_capabilities(profile: Mapping[str, Any]) -> frozenset[str]:
    raw = profile.get("adapter_capabilities")
    capabilities = tuple(raw) if isinstance(raw, (list, tuple)) else ()
    return provider_adapter_capabilities(
        str(profile.get("name") or ""),
        str(profile.get("base_url") or ""),
        capabilities,
    )


def _provider_endpoint_allowed(base_url: str, profile: Mapping[str, Any] | None = None) -> bool:
    profile = profile if isinstance(profile, Mapping) else {}
    return provider_endpoint_allowed(
        base_url,
        profile_name=str(profile.get("name") or ""),
        wire_protocol=str(profile.get("wire_protocol") or "") or None,
        allowed_hosts=tuple(profile.get("allowed_endpoint_hosts") or ()),
    )


def _provider_messages(
    messages: object,
    user_prompt: object,
    wire_protocol: str,
) -> list[dict[str, Any]]:
    if isinstance(messages, list):
        neutral_messages = messages
    elif type(user_prompt) is str:
        neutral_messages = [{"role": "user", "content": user_prompt}]
    else:
        raise AuthorityError("provider messages are incomplete")
    try:
        return provider_messages_for_wire(neutral_messages, wire_protocol)
    except ProviderError as error:
        raise AuthorityError("provider messages are malformed") from error


def _anthropic_tools(tools: object) -> list[dict[str, Any]]:
    try:
        return provider_tools_for_wire(tools, ANTHROPIC_MESSAGES)
    except ProviderError as error:
        raise AuthorityError("provider tools are malformed") from error


class AuthorityError(PermissionError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        reason_code: str | None = None,
    ):
        super().__init__(message)
        if status_code is not None and (type(status_code) is not int or not 100 <= status_code <= 599):
            raise ValueError("authority HTTP status code is invalid")
        if reason_code is not None and (not isinstance(reason_code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,96}", reason_code)):
            raise ValueError("authority reason code is invalid")
        self.status_code = status_code
        self.reason_code = reason_code


class AuthorityService:
    def __init__(self, channel: socket.socket, bootstrap: bytes):
        if len(bootstrap) < 32:
            raise AuthorityError("authority bootstrap is incomplete")
        self.channel = channel
        try:
            decoded_bootstrap = json.loads(bootstrap.decode("utf-8"))
        except Exception:
            decoded_bootstrap = {}
        raw_authority_key = decoded_bootstrap.get("authority_private_key_hex") if isinstance(decoded_bootstrap, Mapping) else None
        try:
            key_bytes = bytes.fromhex(str(raw_authority_key)) if isinstance(raw_authority_key, str) else b""
            if len(key_bytes) != 32:
                raise ValueError("missing controller authority key")
            self._authority_private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        except (ValueError, TypeError) as error:
            raise AuthorityError("controller authority key is invalid") from error
        self._authority_public_key = self._authority_private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self._authority_key_id = "host-ed25519:" + hashlib.sha256(self._authority_public_key).hexdigest()
        self.issuer_id = "code-mode-host-" + hashlib.sha256(self._authority_public_key).hexdigest()[:24]
        # This MAC is only for the bootstrap/runtime binding protocol.  It is
        # never accepted as an authority-operation signature.
        self._binding_mac_key = hashlib.sha256(b"sitina-code-mode-binding-v2\0" + bootstrap).digest()
        reviewer_material = decoded_bootstrap.get("reviewer_verification") if isinstance(decoded_bootstrap, Mapping) else None
        self._reviewer_verification = dict(reviewer_material) if isinstance(reviewer_material, Mapping) else {}
        # These identities are launcher-owned bootstrap facts.  They are not
        # accepted from a later RPC, which prevents a caller from rebinding a
        # valid host session to an arbitrary state root or workspace.
        self._state_root = self._bootstrap_path(decoded_bootstrap, "state_root")
        self._workspace = self._bootstrap_path(decoded_bootstrap, "workspace")
        self._source_root = self._bootstrap_path(decoded_bootstrap, "source_root")
        self._state_root_identity = str(decoded_bootstrap.get("state_root_identity") or "")
        self._workspace_identity = str(decoded_bootstrap.get("workspace_identity") or "")
        self._source_root_identity = str(decoded_bootstrap.get("source_root_identity") or "")
        self._source_manifest_hash = str(decoded_bootstrap.get("source_manifest_hash") or "")
        self._bootstrap_runtime_state_identity = str(decoded_bootstrap.get("runtime_state_identity") or "")
        self._bootstrap_runtime_journal_id = str(decoded_bootstrap.get("runtime_journal_id") or "")
        self._session_instance_id = str(decoded_bootstrap.get("session_instance_id") or "").strip()
        raw_controller_capability_public_key = decoded_bootstrap.get("controller_capability_public_key")
        try:
            self._bootstrap_controller_capability_public_key = bytes.fromhex(
                str(raw_controller_capability_public_key or "")
            )
        except ValueError as error:
            raise AuthorityError("authority bootstrap controller capability key is invalid") from error
        if len(self._bootstrap_controller_capability_public_key) != 32:
            raise AuthorityError("authority bootstrap controller capability key is invalid")
        if not self._session_instance_id:
            raise AuthorityError("authority bootstrap lacks session instance identity")
        if not self._state_root_identity or not self._workspace_identity:
            raise AuthorityError("authority bootstrap lacks fixed root identities")
        if not self._bootstrap_runtime_state_identity or not self._bootstrap_runtime_journal_id:
            raise AuthorityError("authority bootstrap lacks runtime identity")
        self._assert_path_identity(self._state_root, self._state_root_identity, "state root")
        self._assert_path_identity(self._workspace, self._workspace_identity, "workspace")
        if not self._source_root.is_dir() or self._source_root.is_symlink():
            raise AuthorityError("authority bootstrap source root is unavailable")
        self._profiles = dict(decoded_bootstrap.get("profiles") or {}) if isinstance(decoded_bootstrap, Mapping) else {}
        material = decoded_bootstrap.get("verification_material") if isinstance(decoded_bootstrap, Mapping) else None
        try:
            self._verification_provider = (
                InMemoryKeyProvider.from_read_only_verification_material(material)
                if isinstance(material, Mapping) else None
            )
        except Exception as error:
            raise AuthorityError("authority bootstrap verification material is invalid") from error
        self._cas_reader: LocalCAS | None = None
        self._journal_authenticator = (
            JournalAuthProvider(self._verification_provider)
            if self._verification_provider is not None else None
        )
        try:
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            self._identity_fds = {
                "state root": os.open(self._state_root, directory_flags),
                "workspace": os.open(self._workspace, directory_flags),
                "source root": os.open(self._source_root, directory_flags),
            }
        except OSError as error:
            raise AuthorityError("authority bootstrap roots could not be pinned") from error
        self._load_profile_paths(decoded_bootstrap.get("profile_paths") if isinstance(decoded_bootstrap, Mapping) else None)
        challenge = decoded_bootstrap.get("challenge_secret") if isinstance(decoded_bootstrap, Mapping) else None
        self._challenge_secret = bytes.fromhex(challenge) if isinstance(challenge, str) else b""
        self._sessions: dict[str, dict[str, Any]] = {}
        self._canaries: dict[str, dict[str, Any]] = {}
        self._pre_provider_authorizations: dict[str, dict[str, Any]] = {}
        self._pre_provider_handle_mappings: dict[str, dict[str, Any]] = {}
        self._transport: dict[str, list[dict[str, Any]]] = {}
        self._pending: dict[str, dict[str, Any]] = {}
        self._next_sequence = 0
        self._test_acceptance_snapshot_barrier = None
        if os.environ.get("SITINA_CODE_MODE_TEST_HOOKS") == "1":
            candidate_barrier = decoded_bootstrap.get("test_acceptance_snapshot_barrier")
            if isinstance(candidate_barrier, Mapping):
                ready_path = candidate_barrier.get("ready")
                release_path = candidate_barrier.get("release")
                if isinstance(ready_path, str) and isinstance(release_path, str):
                    self._test_acceptance_snapshot_barrier = (ready_path, release_path)

    def _await_test_acceptance_snapshot_barrier(self) -> None:
        """Test-only deterministic race seam; production launchers never set it."""
        barrier = self._test_acceptance_snapshot_barrier
        if barrier is None:
            return
        ready_path, release_path = barrier
        try:
            fd = os.open(ready_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if os.path.exists(release_path):
                return
            time.sleep(0.01)
        raise AuthorityError("test acceptance snapshot barrier timed out")

    @staticmethod
    def _bootstrap_path(value: Mapping[str, Any], key: str) -> Path:
        raw = value.get(key)
        if not isinstance(raw, str) or not raw:
            raise AuthorityError("authority bootstrap lacks " + key)
        path = Path(raw).expanduser().resolve(strict=True)
        if path.is_symlink():
            raise AuthorityError("authority bootstrap path may not be a symlink")
        return path

    @staticmethod
    def _path_identity(path: Path) -> str:
        info = path.stat()
        return f"{info.st_dev}:{info.st_ino}"

    @classmethod
    def _assert_path_identity(cls, path: Path, expected: str, label: str) -> None:
        if cls._path_identity(path) != expected:
            raise AuthorityError(label + " identity changed")

    def _assert_bound_identities(self) -> None:
        """Recheck launcher-bound roots before every authoritative reopen.

        Directory identity alone protects the state/workspace anchors from a
        rename-and-replace.  The source checkout also gets a content identity,
        because its directory inode is intentionally stable while source files
        may change underneath a long-lived host.
        """
        for label, expected in (
            ("state root", self._state_root_identity),
            ("workspace", self._workspace_identity),
            ("source root", self._source_root_identity),
        ):
            fd = getattr(self, "_identity_fds", {}).get(label)
            if not isinstance(fd, int) or fd < 0:
                raise AuthorityError("authority root descriptor is unavailable")
            info = os.fstat(fd)
            if f"{info.st_dev}:{info.st_ino}" != expected:
                raise AuthorityError(label + " identity changed")
        if not self._source_root_identity or not self._source_manifest_hash:
            raise AuthorityError("authority bootstrap lacks a source identity")
        if self._compute_source_manifest_hash() != self._source_manifest_hash:
            raise AuthorityError("source identity changed")

    def _compute_source_manifest_hash(self) -> str:
        paths: list[Path] = []
        config = self._source_root / "config"
        if config.is_dir():
            paths.extend(config.iterdir())
        core = self._source_root / "core" / "sitina"
        if core.is_dir():
            paths.extend(core.rglob("*.py"))
        records: list[dict[str, Any]] = []
        for path in sorted(set(paths), key=lambda item: str(item)):
            relative = str(path.relative_to(self._source_root))
            if path.is_file() and not path.is_symlink():
                records.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
            else:
                records.append({"path": relative, "absent": True})
        return hashlib.sha256(_canonical(records)).hexdigest()

    def _journal_snapshot(self) -> list[Any]:
        """Read the bound Journal frames without trusting RPC projections.

        The host only consumes authenticated Journal payloads for identity
        and frontier derivation.  It never accepts a client-supplied version
        or parent commitment.  Signature verification remains at the owning
        Journal verifier; an unreadable bound Journal is a hard refusal.
        """
        self._assert_bound_identities()
        if self._journal_authenticator is None:
            raise AuthorityError("authority host lacks the formal Journal verifier")
        try:
            return list(LocalJournal.read_authenticated_frames(
                self._state_root,
                self._journal_authenticator,
                journal_id=self._bootstrap_runtime_journal_id,
                epoch=1,
                namespace_kind="code_mode",
            ))
        except Exception as error:
            raise AuthorityError("bound Journal failed formal read-only recovery") from error

    @staticmethod
    def _snapshot_hash(snapshot: list[Any] | tuple[Any, ...]) -> str:
        """Commit one authenticated frame set shared by a host RPC."""
        projection = []
        for frame in snapshot:
            transaction = frame.transaction
            projection.append({
                "transaction_hash": str(getattr(frame, "transaction_hash", "")),
                "transaction_id": str(transaction.transaction_id),
                "command_id": str(transaction.command_id),
                "stream_id": str(transaction.stream_id),
                "first_stream_version": int(transaction.first_stream_version),
                "last_stream_version": int(transaction.last_stream_version),
                "event_hashes": [str(event.event_hash) for event in transaction.events],
            })
        return hashlib.sha256(
            b"SITINA-CODE-MODE-AUTHENTICATED-SNAPSHOT-V1\0" + _canonical(projection)
        ).hexdigest()

    def _formal_cas(self) -> LocalCAS:
        self._assert_bound_identities()
        if self._verification_provider is None:
            raise AuthorityError("authority host lacks the formal CAS verifier")
        if self._cas_reader is None:
            try:
                self._cas_reader = LocalCAS.open_read_only(
                    self._state_root, self._verification_provider, namespace_kind="code_mode"
                )
            except Exception as error:
                raise AuthorityError("bound CAS cannot be opened through the formal verifier") from error
        return self._cas_reader

    def _bound_run(
        self, run_locator: object, *, snapshot: list[Any] | tuple[Any, ...] | None = None,
    ) -> tuple[str, str, str, int]:
        if not isinstance(run_locator, str) or not re.fullmatch(r"run/[A-Za-z0-9._:@-]+", run_locator):
            raise AuthorityError("run locator must be a durable run identifier")
        run_id = run_locator.removeprefix("run/")
        stream_id = run_locator
        frames = snapshot if snapshot is not None else self._journal_snapshot()
        events = [
            event for frame in frames
            if frame.transaction.stream_id == stream_id
            for event in frame.transaction.events
        ]
        if not events:
            raise AuthorityError("run locator is not present in the bound Journal")
        generations = {str(event.payload.get("generation")) for event in events if isinstance(event.payload, Mapping) and event.payload.get("generation") is not None}
        if len(generations) != 1:
            raise AuthorityError("run locator has no unique generation")
        return run_id, stream_id, next(iter(generations)), max(int(event.stream_version) for event in events)

    def _latest_attempt_binding(
        self, snapshot: Sequence[Any], run_id: str,
    ) -> tuple[int, str, Mapping[str, Any]]:
        """Reopen the authenticated execution-attempt chain for transport.

        A canary permit is a snapshot capability, not a timeless bearer
        token.  This deliberately consumes only the durable authorization
        events and validates their contiguous predecessor chain; a caller's
        cached ``attempt`` or ``authorization_ref`` is never authoritative.
        """
        events = [
            event for frame in snapshot
            if frame.transaction.stream_id == f"run/{run_id}"
            for event in frame.transaction.events
            if isinstance(event.payload, Mapping)
            and event.payload.get("run_id") == run_id
            and event.payload.get("event_type") in {
                "execution.authorization.bound",
                "execution.authorization.attempt_advanced",
            }
        ]
        events.sort(key=lambda event: int(event.stream_version))
        if not events:
            raise AuthorityError("current execution authorization is missing")
        root = events[0].payload
        if (
            root.get("schema") != "SITINA_EXECUTION_AUTHORIZATION_V1"
            or root.get("event_type") != "execution.authorization.bound"
            or type(root.get("run_attempt")) is not int
            or root.get("run_attempt") != 1
        ):
            raise AuthorityError("execution authorization root is invalid")
        latest = dict(root)
        expected_attempt = 1
        for event in events[1:]:
            value = event.payload
            if (
                value.get("schema") != "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1"
                or value.get("event_type") != "execution.authorization.attempt_advanced"
                or value.get("previous_run_attempt") != expected_attempt
                or value.get("run_attempt") != expected_attempt + 1
                or value.get("previous_authorization_ref") != latest.get("authorization_ref")
            ):
                raise AuthorityError("execution authorization chain is not contiguous")
            latest = dict(value)
            expected_attempt += 1
        ref = latest.get("authorization_ref")
        if not isinstance(ref, str) or not ref:
            raise AuthorityError("current execution authorization ref is missing")
        return expected_attempt, ref, latest

    @staticmethod
    def _current_execution_authorization(
        attempt: int, latest: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Return the immutable execution binding for the current attempt.

        Attempt-advanced Journal facts are durable wrappers: their top-level
        fields intentionally contain only the lifecycle projection while the
        complete execution authorization (including turn/session/provider
        scope) is nested.  Callers that compare root selections must use this
        nested object rather than treating the wrapper as a complete binding.
        """
        if attempt == 1:
            return latest
        nested = latest.get("execution_authorization")
        if not isinstance(nested, Mapping):
            raise AuthorityError("current attempt lacks its execution authorization")
        for field in (
            "run_id", "run_attempt", "authorization_ref", "session_instance_id",
            "session_id", "turn_index", "generation", "provider_profile", "provider_model",
        ):
            value = nested.get(field)
            if field in {"run_attempt", "turn_index"}:
                if type(value) is not int or value < (1 if field == "run_attempt" else 0):
                    raise AuthorityError("current attempt execution authorization has invalid " + field)
            elif not isinstance(value, str) or not value:
                raise AuthorityError("current attempt execution authorization has missing " + field)
        if nested.get("run_attempt") != attempt or nested.get("run_id") != latest.get("run_id"):
            raise AuthorityError("current attempt execution authorization scope changed")
        if nested.get("authorization_ref") != latest.get("authorization_ref"):
            raise AuthorityError("current attempt execution authorization ref changed")
        return nested

    @staticmethod
    def _validate_canary_attempt_provider_binding(
        *,
        latest_attempt: int,
        latest_authorization_ref: str,
        latest_authorization: Mapping[str, Any],
        expected_scope: Mapping[str, Any],
        pre_provider_scope: object,
    ) -> None:
        """Require the canary tuple from the authenticated current attempt.

        The attempt-one event is the execution authorization itself.  An
        attempt-advanced event is a durable wrapper around its nested
        ``execution_authorization``; its top-level projection intentionally
        does not carry bearer/provider fields.  This helper is kept before
        permit signing and capability consumption so an absent or malformed
        nested fact cannot become an optional binding check.
        """
        expected_provider_tuple = (
            expected_scope.get("provider_profile"),
            expected_scope.get("provider_model"),
        )
        if (
            type(latest_attempt) is not int
            or latest_attempt < 1
            or latest_attempt != expected_scope.get("run_attempt")
        ):
            raise AuthorityError("canary provider binding uses a stale execution attempt")
        if latest_attempt == 1:
            current_execution_authorization = latest_authorization
        else:
            nested_execution_authorization = latest_authorization.get("execution_authorization")
            if not isinstance(nested_execution_authorization, Mapping):
                raise AuthorityError("current attempt lacks its execution authorization")
            if (
                type(nested_execution_authorization.get("run_attempt")) is not int
                or nested_execution_authorization.get("run_attempt") != latest_authorization.get("run_attempt")
                or type(nested_execution_authorization.get("authorization_ref")) is not str
                or not nested_execution_authorization.get("authorization_ref")
                or nested_execution_authorization.get("authorization_ref") != latest_authorization.get("authorization_ref")
            ):
                raise AuthorityError("current attempt execution authorization is not exact")
            current_execution_authorization = nested_execution_authorization
        current_provider_tuple = (
            current_execution_authorization.get("provider_profile"),
            current_execution_authorization.get("provider_model"),
        )
        if (
            type(current_provider_tuple[0]) is not str
            or not current_provider_tuple[0]
            or type(current_provider_tuple[1]) is not str
            or not current_provider_tuple[1]
            or current_provider_tuple != expected_provider_tuple
        ):
            raise AuthorityError("canary provider binding differs from current authorization")
        code_mode_authorization = latest_authorization.get("code_mode_authorization")
        if code_mode_authorization is not None:
            if not isinstance(code_mode_authorization, Mapping):
                raise AuthorityError("current durable Code Mode authorization is invalid")
            code_mode_provider_tuple = (
                code_mode_authorization.get("provider_profile"),
                code_mode_authorization.get("provider_model"),
            )
            if any(value is not None for value in code_mode_provider_tuple):
                if (
                    type(code_mode_provider_tuple[0]) is not str
                    or not code_mode_provider_tuple[0]
                    or type(code_mode_provider_tuple[1]) is not str
                    or not code_mode_provider_tuple[1]
                    or code_mode_provider_tuple != current_provider_tuple
                ):
                    raise AuthorityError("canary provider binding differs from durable authorization")
        if not isinstance(pre_provider_scope, Mapping):
            raise AuthorityError("canary pre-provider authorization scope is missing")
        required_scope_fields = (
            "session_instance_id", "conversation_session_id", "turn_index", "run_id",
            "run_attempt", "generation", "provider_profile", "provider_model",
        )
        for field in required_scope_fields:
            actual = pre_provider_scope.get(field)
            # This is the root-planning grant, intentionally fixed to
            # attempt one.  Rework attempts use a new execution authorization
            # and must not be forced to rewrite the root provider scope.
            expected = 1 if field == "run_attempt" else expected_scope.get(field)
            if field == "turn_index":
                valid_type = type(actual) is int
            elif field == "run_attempt":
                valid_type = type(actual) is int and actual == 1
            else:
                valid_type = type(actual) is str and bool(actual)
            if not valid_type or actual != expected:
                raise AuthorityError("canary pre-provider authorization scope changed")

    def _run_created_binding(
        self, snapshot: Sequence[Any], run_id: str,
        *, pre_provider_scope: Mapping[str, Any] | None = None,
    ) -> tuple[int, str, Mapping[str, Any]]:
        """Reopen the pre-Forge run binding before Forge authorization exists.

        Root planning calls are intentionally admitted before the Forge
        execution authorization is created.  At that point the durable
        ``run.created`` fact is the run/session frontier; requiring the later
        execution-authorization root here would create a circular dependency
        and would reject the first legitimate Provider call.  The fact is
        still reopened from the authenticated Journal and its Code Mode
        controls are required-exact, so this is not a caller-supplied scalar
        fallback.
        """
        events = [
            event for frame in snapshot
            if frame.transaction.stream_id == f"run/{run_id}"
            for event in frame.transaction.events
            if isinstance(event.payload, Mapping)
            and event.payload.get("event_type") == "run.created"
            and event.payload.get("run_id") == run_id
        ]
        if len(events) != 1:
            raise AuthorityError("pre-provider run binding is not unique")
        payload = events[0].payload
        controls = payload.get("acceptance_controls")
        if not isinstance(controls, Mapping):
            raise AuthorityError("pre-provider run binding has no durable controls")
        authorization = controls.get("code_mode_authorization")
        root_projection = controls.get("root_pre_provider_binding")
        if authorization is not None and not isinstance(authorization, Mapping):
            raise AuthorityError("current durable Code Mode authorization is invalid")
        if root_projection is not None and not isinstance(root_projection, Mapping):
            raise AuthorityError("durable root pre-provider binding is invalid")
        if not isinstance(authorization, Mapping) and not isinstance(root_projection, Mapping):
            raise AuthorityError("pre-provider run binding has no issuer-bound root scope")
        scope = root_projection if isinstance(root_projection, Mapping) else authorization
        session_instance_id = controls.get("session_instance_id") or scope.get("session_instance_id")
        session_id = controls.get("conversation_session_id") or scope.get("conversation_session_id") or scope.get("session_id")
        generation = scope.get("generation")
        if isinstance(pre_provider_scope, Mapping):
            expected_fields = (
                "session_instance_id", "conversation_session_id", "turn_index", "run_id",
                "run_attempt", "generation", "provider_profile", "provider_model",
            )
            if any(
                field in scope and scope.get(field) != pre_provider_scope.get(field)
                for field in expected_fields
            ):
                raise AuthorityError("durable root pre-provider binding differs from issuer scope")
        if (
            not isinstance(session_instance_id, str) or not session_instance_id
            or not isinstance(session_id, str) or not session_id
            or not isinstance(generation, str) or not generation
            or scope.get("run_id") not in (None, run_id)
        ):
            raise AuthorityError("pre-provider run binding is incomplete")
        if (
            type(scope.get("turn_index", controls.get("conversation_turn_index"))) is not int
            or type(scope.get("run_attempt", 1)) is not int
            or scope.get("run_attempt", 1) != 1
            or scope.get("conversation_session_id", session_id) != session_id
        ):
            raise AuthorityError("pre-provider run binding scope is incomplete")
        return 1, "", {
            "run_id": run_id,
            "session_instance_id": session_instance_id,
            "session_id": session_id,
            "generation": generation,
            "run_attempt": 1,
            "turn_index": scope.get("turn_index", controls.get("conversation_turn_index")),
            "provider_profile": scope.get("provider_profile"),
            "provider_model": scope.get("provider_model"),
        }

    @staticmethod
    def _root_fact_events(snapshot: Sequence[Any], run_id: str, schema: str, event_type: str) -> list[Mapping[str, Any]]:
        """Return only authenticated facts from the bound root stream."""
        values: list[Mapping[str, Any]] = []
        for frame in snapshot:
            if frame.transaction.stream_id != f"run/{run_id}":
                continue
            for event in frame.transaction.events:
                payload = event.payload
                if (
                    isinstance(payload, Mapping)
                    and payload.get("schema") == schema
                    and payload.get("event_type") == event_type
                    and payload.get("run_id") == run_id
                ):
                    values.append(payload)
        return values

    def _root_proposal_rework_state(
        self, snapshot: Sequence[Any], run_id: str,
    ) -> Mapping[str, Any] | None:
        """Reopen the single authorized proposal-revision transition.

        Root planning normally closes at WAIT_SELECTION after the first
        review. A Code Mode write may instead have one concrete NEEDS_CHANGES
        disposition. This reads protocol Journal facts (never a caller flag)
        and returns the one exact next root task.
        """
        events: list[Mapping[str, Any]] = []
        prefix = f"protocol/{run_id}/proposal/"
        for frame in snapshot:
            if not frame.transaction.stream_id.startswith(prefix):
                continue
            for event in frame.transaction.events:
                payload = event.payload
                if not isinstance(payload, Mapping):
                    continue
                if payload.get("run_id") not in (None, run_id):
                    continue
                if payload.get("event_type") in {
                    "proposal.submitted", "proposal.revised", "review.response",
                    "review.disposition",
                }:
                    events.append(payload)
        submissions = [item for item in events if item.get("event_type") == "proposal.submitted"]
        revisions = [item for item in events if item.get("event_type") == "proposal.revised"]
        dispositions = [item for item in events if item.get("event_type") == "review.disposition"]
        responses = [item for item in events if item.get("event_type") == "review.response"]
        if len(revisions) > 1:
            raise AuthorityError("proposal revision budget exceeded", reason_code="ROOT_REWORK_BUDGET_EXCEEDED")
        needs = [item for item in dispositions if item.get("disposition") == "NEEDS_CHANGES"]
        if not needs:
            return None
        if len(needs) != 1:
            raise AuthorityError(
                "proposal rework has multiple NEEDS_CHANGES dispositions",
                reason_code="ROOT_REWORK_MULTIPLE_NEEDS_CHANGES",
            )
        disposition = needs[0]
        run_created = [
            event.payload
            for frame in snapshot
            if frame.transaction.stream_id == f"run/{run_id}"
            for event in frame.transaction.events
            if isinstance(event.payload, Mapping)
            and event.payload.get("event_type") == "run.created"
            and event.payload.get("run_id") == run_id
        ]
        controls = run_created[0].get("acceptance_controls") if len(run_created) == 1 else None
        code_auth = controls.get("code_mode_authorization") if isinstance(controls, Mapping) else None
        intent = code_auth.get("intent") if isinstance(code_auth, Mapping) else None
        if (
            disposition.get("code_mode_mutation_rework") is not True
            or disposition.get("risk_level") != "low"
            or disposition.get("revision_budget") != 1
            or not isinstance(code_auth, Mapping)
            or code_auth.get("intent_authorized") is not True
            or not isinstance(intent, Mapping)
            or intent.get("explicit_mutation") is not True
        ):
            # Ordinary MULTI review/rework is not a root transport
            # authorization. Only the explicit low-risk Code Mode write seam
            # may reopen one revision before selection.
            return None
        review_id = disposition.get("review_id")
        artifact_hash = disposition.get("artifact_hash")
        response = next((item for item in responses if item.get("review_id") == review_id), None)
        if (
            not isinstance(review_id, str) or not review_id
            or not isinstance(artifact_hash, str) or not artifact_hash
            or not isinstance(response, Mapping)
        ):
            raise AuthorityError("NEEDS_CHANGES review is not durably bound", reason_code="ROOT_REWORK_BINDING_MISSING")
        proposal = next((item for item in submissions if item.get("body_ref") == artifact_hash), None)
        if not isinstance(proposal, Mapping):
            raise AuthorityError("NEEDS_CHANGES review has no submitted proposal", reason_code="ROOT_REWORK_PROPOSAL_MISSING")
        reviewer_id = response.get("reviewer_id")
        review_output_hash = response.get("review_output_hash")
        author_id = proposal.get("participant_id")
        original_defects = disposition.get("frozen_defects")
        if (
            not isinstance(reviewer_id, str) or not reviewer_id
            or not isinstance(review_output_hash, str) or not review_output_hash
            or not isinstance(author_id, str) or not author_id
            or response.get("verdict") != "NEEDS_CHANGES"
            or response.get("effective_verdict") not in (None, "changes_requested")
            or not isinstance(original_defects, list)
            or not original_defects
            or any(type(item) is not str or not item.strip() for item in original_defects)
        ):
            raise AuthorityError(
                "NEEDS_CHANGES reviewer response is contradictory",
                reason_code="ROOT_REWORK_RESPONSE_CONTRADICTORY",
            )
        proposal_id = proposal.get("proposal_id")
        matching_revisions = [item for item in revisions if item.get("proposal_id") == proposal_id]
        if not matching_revisions:
            return {
                "state": "EXPECT_REVISION",
                "proposal_id": proposal_id,
                "author_id": author_id,
                "review_id": review_id,
                "reviewer_id": reviewer_id,
                "review_output_hash": review_output_hash,
                "artifact_hash": artifact_hash,
                "revision_budget": 1,
            }
        if len(matching_revisions) != 1:
            raise AuthorityError("proposal rework has a non-unique revision", reason_code="ROOT_REWORK_REVISION_NOT_UNIQUE")
        revision = matching_revisions[0]
        if (
            revision.get("revision") != 2
            or revision.get("review_id") != review_id
            or revision.get("reviewer_id") != reviewer_id
            or revision.get("review_output_hash") != review_output_hash
            or not isinstance(revision.get("frozen_defects"), list)
            or not revision.get("frozen_defects")
            or revision.get("frozen_defects") != original_defects
            or not isinstance(revision.get("body_ref"), str)
            or not revision.get("body_ref")
        ):
            raise AuthorityError(
                "proposal revision is not bound to the original review defects",
                reason_code="ROOT_REWORK_DEFECT_BINDING_MISMATCH",
            )
        revised_hash = revision.get("body_ref")
        second_dispositions = [
            item for item in dispositions
            if item.get("artifact_hash") == revised_hash and item.get("review_id") != review_id
        ]
        second_ids = {item.get("review_id") for item in second_dispositions}
        second_responses = [item for item in responses if item.get("review_id") in second_ids]
        if not second_dispositions:
            return {
                "state": "EXPECT_REVISION_REVIEW",
                "proposal_id": proposal_id,
                "author_id": author_id,
                "review_id": review_id,
                "reviewer_id": reviewer_id,
                "revision_hash": revised_hash,
                "revision_budget": 1,
            }
        if len(second_dispositions) != 1 or len(second_responses) != 1:
            raise AuthorityError("proposal second review is not unique", reason_code="ROOT_REWORK_SECOND_REVIEW_NOT_UNIQUE")
        second_response = second_responses[0]
        if (
            second_response.get("reviewer_id") != reviewer_id
            or second_response.get("verdict") != "ACCEPT"
            or second_dispositions[0].get("disposition") != "ACCEPT"
        ):
            return {"state": "CLOSED_REJECTED", "revision_budget": 1}
        return {"state": "CLOSED", "revision_budget": 1}

    def _root_fsm_from_snapshot(self, snapshot: Sequence[Any], run_id: str) -> str:
        """Recompute the root FSM from authenticated producer facts.

        A transport receipt only proves that HTTP settled.  The business FSM
        advances only after the result was contract-checked and Task.accept
        emitted its dedicated result-accepted fact.  Scheduling and dispatch
        facts are also required for every call, so a caller cannot skip from
        the proposal state directly to review or selection.
        """
        scheduling = self._root_fact_events(
            snapshot, run_id, "AGENT_SCHEDULING_DECISION_V1", "scheduling.decision"
        )
        dispatch_acceptance = self._root_fact_events(
            snapshot, run_id, "DISPATCH_COMMAND_ACCEPTED_V1", "dispatch.command.accepted"
        )
        dispatches = self._root_fact_events(
            snapshot, run_id, "CODE_MODE_ROOT_DISPATCH_FACT_V1", "code-mode.root-call-dispatched"
        )
        settled = self._root_fact_events(
            snapshot, run_id, "CODE_MODE_ROOT_SETTLED_FACT_V1", "code-mode.root-call-settled"
        )
        result_accepted = self._root_fact_events(
            snapshot, run_id, "CODE_MODE_ROOT_RESULT_ACCEPTED_V1", "code-mode.root-result-accepted"
        )
        schedule_by_id: dict[str, Mapping[str, Any]] = {}
        for fact in scheduling:
            decision_id = fact.get("decision_id")
            if not isinstance(decision_id, str) or not decision_id or decision_id in schedule_by_id:
                raise AuthorityError("root scheduling facts are not unique")
            if fact.get("purpose") != "code-mode-agent-scheduling" or fact.get("purpose_class") != "code-mode-agent-scheduling-decision":
                raise AuthorityError("root scheduling fact purpose is invalid")
            decision = fact.get("decision")
            if not isinstance(decision, Mapping) or decision.get("decision_id") != decision_id or decision.get("decision_commitment") != fact.get("decision_commitment"):
                raise AuthorityError("root scheduling decision commitment is not exact")
            if (
                type(fact.get("turn_index")) is not int
                or type(fact.get("requested_slots")) is not int
                or type(fact.get("run_attempt")) is not int
                or fact.get("run_attempt") < 1
                or not isinstance(fact.get("required_capabilities"), list)
            ):
                raise AuthorityError("root scheduling numeric binding is invalid")
            if not isinstance(fact.get("selected_agents"), list) or not fact.get("selected_agents"):
                raise AuthorityError("root scheduling has no selected agents")
            schedule_by_id[decision_id] = fact
        dispatch_by_id: dict[str, Mapping[str, Any]] = {}
        for fact in dispatch_acceptance:
            decision_id = fact.get("decision_id")
            if not isinstance(decision_id, str) or decision_id in dispatch_by_id:
                raise AuthorityError("root dispatch command facts are not unique")
            schedule = schedule_by_id.get(decision_id)
            if schedule is None or fact.get("decision_commitment") != schedule.get("decision_commitment"):
                raise AuthorityError("root dispatch command has no exact scheduling predecessor")
            if fact.get("task_id") != schedule.get("task_id") or fact.get("phase") != schedule.get("phase"):
                raise AuthorityError("root dispatch command task or phase changed")
            for field in (
                "run_id", "session_instance_id", "conversation_session_id", "turn_index",
                "generation", "run_attempt", "required_capabilities",
            ):
                if fact.get(field) != schedule.get(field):
                    raise AuthorityError("root dispatch command lineage changed")
            if fact.get("selected_agents") != schedule.get("selected_agents") or fact.get("requested_slots") != schedule.get("requested_slots"):
                raise AuthorityError("root dispatch command selection changed")
            if fact.get("state") != "ACCEPTED" or not isinstance(fact.get("dispatch_command_id"), str) or not isinstance(fact.get("dispatch_commitment"), str):
                raise AuthorityError("root dispatch command state is invalid")
            dispatch_by_id[decision_id] = fact
        by_call: dict[str, Mapping[str, Any]] = {}
        for fact in dispatches:
            call_id = fact.get("provider_call_id")
            if not isinstance(call_id, str) or not call_id or call_id in by_call:
                raise AuthorityError("root dispatch producer facts are not unique")
            schedule = schedule_by_id.get(fact.get("scheduling_decision_id"))
            dispatch_command = dispatch_by_id.get(fact.get("scheduling_decision_id"))
            if schedule is None or dispatch_command is None:
                raise AuthorityError("root dispatch has no authenticated scheduling/dispatch predecessor")
            if (
                fact.get("run_attempt") != schedule.get("run_attempt")
                or fact.get("run_id") != schedule.get("run_id")
                or fact.get("session_instance_id") != schedule.get("session_instance_id")
                or fact.get("conversation_session_id") != schedule.get("conversation_session_id")
                or fact.get("turn_index") != schedule.get("turn_index")
                or fact.get("generation") != schedule.get("generation")
                or fact.get("scheduling_task_id") != schedule.get("task_id")
                or fact.get("scheduling_decision_commitment") != schedule.get("decision_commitment")
                or fact.get("dispatch_command_id") != dispatch_command.get("dispatch_command_id")
                or fact.get("dispatch_command_commitment") != dispatch_command.get("dispatch_commitment")
                or fact.get("dispatch_commitment") != dispatch_command.get("dispatch_commitment")
                or fact.get("selected_agent_id") not in schedule.get("selected_agents", ())
                or type(fact.get("slot")) is not int
                or fact.get("slot") != list(schedule.get("selected_agents", ())).index(fact.get("selected_agent_id")) + 1
            ):
                raise AuthorityError("root dispatch does not bind its authenticated scheduling slot")
            by_call[call_id] = fact
        settled_by_call: dict[str, Mapping[str, Any]] = {}
        for fact in settled:
            call_id = fact.get("provider_call_id")
            if not isinstance(call_id, str) or not call_id or call_id in settled_by_call:
                raise AuthorityError("root settled producer facts are not unique")
            dispatch = by_call.get(call_id)
            if dispatch is None:
                raise AuthorityError("root settled fact has no authenticated dispatch")
            for field in (
                "session_instance_id", "conversation_session_id", "turn_index", "generation",
                "run_attempt",
                "agent_id", "task_id", "role", "phase", "call_index", "dispatch_commitment",
                "predecessor_identity", "pre_provider_call_identity", "provider_profile",
                "provider_model", "provider_call_id",
                "scheduling_task_id", "scheduling_decision_id", "scheduling_decision_commitment",
                "dispatch_command_id", "dispatch_command_commitment", "selected_agent_id", "slot",
            ):
                if type(fact.get(field)) is not type(dispatch.get(field)) or fact.get(field) != dispatch.get(field):
                    raise AuthorityError("root settled fact does not close its dispatch")
            if fact.get("state") != "SETTLED":
                raise AuthorityError("root settled producer state is invalid")
            settled_by_call[call_id] = fact
        accepted_by_call: dict[str, Mapping[str, Any]] = {}
        for fact in result_accepted:
            call_id = fact.get("provider_call_id")
            if not isinstance(call_id, str) or not call_id or call_id in accepted_by_call:
                raise AuthorityError("root result-accepted facts are not unique")
            settled_fact = settled_by_call.get(call_id)
            dispatch_fact = by_call.get(call_id)
            if settled_fact is None or dispatch_fact is None:
                raise AuthorityError("root result-accepted fact has no settled dispatch")
            for field in (
                "session_instance_id", "conversation_session_id", "turn_index", "generation",
                "run_attempt",
                "agent_id", "task_id", "role", "phase", "call_index", "provider_call_id",
                "scheduling_task_id", "scheduling_decision_id", "scheduling_decision_commitment",
                "dispatch_command_id", "dispatch_command_commitment", "dispatch_commitment",
            ):
                if fact.get(field) != dispatch_fact.get(field) or fact.get(field) != settled_fact.get(field):
                    raise AuthorityError("root result-accepted fact does not close its dispatch")
            if (
                fact.get("response_id") != settled_fact.get("response_id")
                or fact.get("response_receipt_hash") != settled_fact.get("response_receipt_hash")
            ):
                raise AuthorityError("root result-accepted fact changed the settled response")
            if fact.get("state") != "ACCEPTED" or not all(
                isinstance(fact.get(field), str) and fact.get(field)
                for field in ("response_id", "response_receipt_hash", "output_ref", "output_hash", "task_attempt_id")
            ):
                raise AuthorityError("root result-accepted binding is incomplete")
            accepted_by_call[call_id] = fact
        ordered = sorted(settled_by_call.values(), key=lambda value: value.get("call_index", 0))
        expected_index = 1
        phases: list[str] = []
        for fact in ordered:
            if fact.get("call_index") != expected_index:
                raise AuthorityError("root settled call index is not contiguous")
            if fact.get("provider_call_id") not in accepted_by_call:
                raise AuthorityError("root settled call has no accepted business result")
            phase = fact.get("phase")
            if phase not in CODE_MODE_PRE_PROVIDER_PHASES:
                raise AuthorityError("root settled phase is not fixed")
            phases.append(str(phase))
            expected_index += 1
        if not ordered:
            return "EXPECT_DISCOVERY"
        rework_state = self._root_proposal_rework_state(snapshot, run_id)
        if isinstance(rework_state, Mapping) and rework_state.get("state") == "CLOSED_REJECTED":
            # A rejected second review is terminal for this bounded rework;
            # never let the generic proposal counters reopen root admission.
            return "CLOSED_REJECTED"
        if isinstance(rework_state, Mapping) and rework_state.get("state") == "CLOSED":
            # Revision produces a second proposal/review pair.  Its schedule
            # count is not necessarily reflected in legacy required_reviews,
            # so derive the post-review state from the authenticated selection
            # fact directly instead of falling through to EXPECT_PROPOSAL.
            selections = self._root_fact_events(
                snapshot, run_id, "CODE_MODE_ROOT_SELECTION_FACT_V1", "code-mode.root-selection-committed"
            )
            if len(selections) > 1:
                raise AuthorityError("root selection facts are not unique")
            return "ROOT_COMPLETE" if selections else "WAIT_SELECTION"
        if isinstance(rework_state, Mapping) and rework_state.get("state") in {
            "EXPECT_REVISION", "EXPECT_REVISION_REVIEW",
        }:
            return str(rework_state["state"])
        # FAST is an authenticated one-call synthesis workflow.  It shares
        # the root permit/ledger with MULTI, but intentionally has no
        # discovery/proposal/review/selection sequence to complete.
        if len(phases) == 1 and phases[0] == CODE_MODE_FAST_PRE_PROVIDER_PHASE:
            if (
                len(scheduling) != 1
                or scheduling[0].get("phase") != CODE_MODE_FAST_PRE_PROVIDER_PHASE
                or scheduling[0].get("task_id") != "conversation-answer"
                or scheduling[0].get("requested_slots") != 1
                or len(scheduling[0].get("selected_agents", ())) != 1
            ):
                raise AuthorityError("FAST root planning facts are not a single authenticated synthesis call")
            return "ROOT_COMPLETE"
        if phases[0] != "discovery/controller":
            raise AuthorityError("root planning did not settle discovery first")
        if len(phases) == 1:
            return "EXPECT_PROPOSAL"
        proposal_schedules = [item for item in scheduling if item.get("phase") == "proposal/planner/candidate"]
        review_schedules = [item for item in scheduling if item.get("phase") == "review/selection"]
        proposal_calls = [
            fact for fact in ordered[1:]
            if fact.get("phase") == "proposal/planner/candidate"
        ]
        required_proposals = sum(len(item.get("selected_agents", ())) for item in proposal_schedules)
        if any(phase not in {"proposal/planner/candidate", "review/selection"} for phase in phases[1:]):
            raise AuthorityError("root planning phase sequence is invalid")
        if len(proposal_calls) < required_proposals:
            return "EXPECT_PROPOSAL"
        review_calls = [fact for fact in ordered if fact.get("phase") == "review/selection"]
        required_reviews = sum(len(item.get("selected_agents", ())) for item in review_schedules)
        if review_schedules and len(review_calls) < required_reviews:
            return "EXPECT_REVIEW"
        if review_schedules and len(review_calls) == required_reviews:
            selections = self._root_fact_events(
                snapshot, run_id, "CODE_MODE_ROOT_SELECTION_FACT_V1", "code-mode.root-selection-committed"
            )
            if selections:
                if len(selections) != 1:
                    raise AuthorityError("root selection facts are not unique")
                return "ROOT_COMPLETE"
            return "WAIT_SELECTION"
        return "EXPECT_PROPOSAL"

    def _require_root_dispatch(
        self, snapshot: Sequence[Any], run_id: str, request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        provider_call_id = request.get("provider_call_id")
        if not isinstance(provider_call_id, str) or not provider_call_id:
            raise AuthorityError("root dispatch provider call identity is required")
        facts = [
            fact for fact in self._root_fact_events(
                snapshot, run_id, "CODE_MODE_ROOT_DISPATCH_FACT_V1", "code-mode.root-call-dispatched"
            ) if fact.get("provider_call_id") == provider_call_id
        ]
        if len(facts) != 1:
            raise AuthorityError("root call requires one authenticated dispatch producer fact")
        fact = facts[0]
        for field in (
            "session_instance_id", "conversation_session_id", "turn_index", "generation",
            "agent_id", "task_id", "role", "phase", "call_index", "dispatch_commitment",
            "predecessor_identity", "pre_provider_call_identity", "provider_profile",
            "provider_model", "provider_call_id",
            "scheduling_task_id", "scheduling_decision_id", "scheduling_decision_commitment",
            "dispatch_command_id", "dispatch_command_commitment", "selected_agent_id", "slot",
        ):
            if request.get(field) != fact.get(field):
                raise AuthorityError(
                    "root call does not match authenticated dispatch fact: " + field
                )
        if fact.get("state") != "DISPATCHED":
            raise AuthorityError("root dispatch producer state is invalid")
        schedule = next(
            (
                item for item in self._root_fact_events(
                    snapshot, run_id, "AGENT_SCHEDULING_DECISION_V1", "scheduling.decision"
                ) if item.get("decision_id") == fact.get("scheduling_decision_id")
            ),
            None,
        )
        dispatch_command = next(
            (
                item for item in self._root_fact_events(
                    snapshot, run_id, "DISPATCH_COMMAND_ACCEPTED_V1", "dispatch.command.accepted"
                ) if item.get("decision_id") == fact.get("scheduling_decision_id")
            ),
            None,
        )
        if (
            schedule is None or dispatch_command is None
            or fact.get("scheduling_task_id") != schedule.get("task_id")
            or fact.get("scheduling_decision_commitment") != schedule.get("decision_commitment")
            or fact.get("dispatch_command_id") != dispatch_command.get("dispatch_command_id")
            or fact.get("dispatch_command_commitment") != dispatch_command.get("dispatch_commitment")
            or fact.get("dispatch_commitment") != dispatch_command.get("dispatch_commitment")
            or fact.get("selected_agent_id") not in schedule.get("selected_agents", ())
        ):
            raise AuthorityError("root dispatch lacks exact scheduling/dispatch acceptance binding")
        return fact

    def _bound_conversation(
        self, locator: object, *, session_id: str | None = None,
        turn_index: int | None = None, run_id: str | None = None,
        session_instance_id: str | None = None, run_attempt: int | None = None,
        generation: str | None = None, message_hash: str | None = None,
        snapshot: list[Any] | tuple[Any, ...] | None = None,
    ) -> tuple[str, int]:
        if not isinstance(locator, str) or not re.fullmatch(r"session/[A-Za-z0-9._:@-]+", locator):
            raise AuthorityError("conversation locator must be a durable session identifier")
        frames = snapshot if snapshot is not None else self._journal_snapshot()
        events = [
            event for frame in frames
            if frame.transaction.stream_id == locator for event in frame.transaction.events
        ]
        if not events:
            raise AuthorityError("conversation locator is not present in the bound Journal")
        if session_id is not None:
            if locator != "session/" + session_id:
                raise AuthorityError("conversation locator is not bound to the request session")
            if type(turn_index) is not int or turn_index < 0 or not isinstance(run_id, str) or not run_id:
                raise AuthorityError("conversation binding scope is incomplete")
            scoped_messages = [
                event for event in events
                if event.event_type == "session.message-appended"
                and isinstance(event.payload, Mapping)
                and event.payload.get("schema") == "SESSION_MESSAGE_APPENDED_V1"
                and event.payload.get("session_id") == session_id
                and event.payload.get("role") == "user"
                and type(event.payload.get("turn_index")) is int
                and event.payload.get("turn_index") == turn_index
            ]
            scoped_links = [
                event for event in events
                if event.event_type == "session.run-linked"
                and isinstance(event.payload, Mapping)
                and event.payload.get("schema") == "SESSION_RUN_LINKED_V1"
                and event.payload.get("session_id") == session_id
                and type(event.payload.get("turn_index")) is int
                and event.payload.get("turn_index") == turn_index
            ]
            messages = [
                event for event in scoped_messages
                if event.payload.get("session_instance_id") == session_instance_id
                and event.payload.get("run_attempt") == run_attempt
                and event.payload.get("generation") == generation
            ]
            links = [
                event for event in scoped_links
                if event.payload.get("run_id") == run_id
                and event.payload.get("session_instance_id") == session_instance_id
                and event.payload.get("run_attempt") == run_attempt
                and event.payload.get("generation") == generation
            ]
            if len(scoped_messages) != 1 or len(scoped_links) != 1 or len(messages) != 1 or len(links) != 1:
                raise AuthorityError("conversation must have one authenticated user message and run link")
            message = messages[0].payload
            link = links[0].payload
            for field, expected in (
                ("session_instance_id", session_instance_id),
                ("run_attempt", run_attempt),
                ("generation", generation),
            ):
                if expected is not None and link.get(field) != expected:
                    raise AuthorityError("conversation " + field + " binding is missing")
                if expected is not None and message.get(field) != expected:
                    raise AuthorityError("conversation " + field + " message binding changed")
            workspace = link.get("workspace")
            if not isinstance(workspace, str) or workspace not in {str(self._workspace), self._workspace_identity}:
                raise AuthorityError("conversation run link workspace is not bound to the host workspace")
            body_ref = message.get("body_ref")
            body_hash = message.get("body_hash")
            if not isinstance(body_ref, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", body_ref):
                raise AuthorityError("conversation user message has no durable body reference")
            if not isinstance(body_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", body_hash):
                raise AuthorityError("conversation user message hash is invalid")
            if message_hash is not None and body_hash != message_hash:
                raise AuthorityError("conversation user message is not the request message")
            try:
                cas = self._formal_cas()
                proof = cas.verify_existing(cas.resolve_reference(body_ref))
                if proof.purpose_class != "session-message":
                    raise AuthorityError("conversation body purpose is not session-message")
                raw = cas.open_verified(cas.resolve_reference(body_ref))
            except AuthorityError:
                raise
            except Exception as error:
                raise AuthorityError("conversation user message cannot be reopened") from error
            if hashlib.sha256(raw).hexdigest() != body_hash:
                raise AuthorityError("conversation user message body hash changed")
        return locator, max(int(event.stream_version) for event in events)

    def _lock_session_scope(
        self, session: Mapping[str, Any], *, run_id: str, generation: str,
        session_id: str, stream_id: str, session_instance_id: str,
        run_attempt: int, authorization_ref: str,
    ) -> None:
        """Pin one live CLI/attempt scope and its authenticated latest ref."""
        current = session.get("scope")
        if (
            not isinstance(session_instance_id, str) or not session_instance_id
            or not isinstance(session_id, str) or not session_id
            or not isinstance(stream_id, str) or not stream_id
            or type(run_attempt) is not int or run_attempt < 1
            or not isinstance(authorization_ref, str) or not authorization_ref
        ):
            raise AuthorityError("authority session scope lacks conversation binding")
        scope = (
            str(session_instance_id), str(run_id), str(generation), str(session_id), str(stream_id),
            self._workspace_identity, self._state_root_identity,
        )
        if current is None:
            # The session mapping is owned by this service, not by the RPC
            # caller.  Later locator requests may narrow the scope, but may
            # never move it to another run, generation, or root.
            session["scope"] = scope  # type: ignore[index]
            session["latest_attempt"] = run_attempt  # type: ignore[index]
            session["latest_authorization_ref"] = authorization_ref  # type: ignore[index]
        elif tuple(current) != scope:
            raise AuthorityError("authority session scope changed")
        else:
            prior_attempt = session.get("latest_attempt")
            prior_ref = session.get("latest_authorization_ref")
            if type(prior_attempt) is not int or not isinstance(prior_ref, str) or not prior_ref:
                raise AuthorityError("authority session latest attempt binding is missing")
            if run_attempt < prior_attempt:
                raise AuthorityError("authority session attempt regressed")
            if run_attempt == prior_attempt and authorization_ref != prior_ref:
                raise AuthorityError("authority session authorization ref changed")
            if run_attempt > prior_attempt:
                session["latest_attempt"] = run_attempt  # type: ignore[index]
                session["latest_authorization_ref"] = authorization_ref  # type: ignore[index]

    @staticmethod
    def _payload_content_hash(payload: Mapping[str, Any]) -> str | None:
        value = payload.get("content_hash")
        if not isinstance(value, str):
            return None
        return value.removeprefix("sha256:")

    def _validate_reopened_facts(
        self,
        *, run_id: str, generation: str, locators: Mapping[str, str],
        resolved: Mapping[str, Mapping[str, Any]],
        snapshot: list[Any] | tuple[Any, ...] | None = None,
    ) -> None:
        """Validate semantic bindings after formal CAS reopening.

        CAS authenticity proves bytes and purpose; this second, shared host
        check proves that the seven typed objects describe one current review.
        It intentionally consumes only reopened payloads, never RPC-provided
        scalar projections.
        """
        expected_schema = {
            "request_locator": "CODE_MODE_REVIEW_REQUEST_V2",
            "candidate_locator": "CODE_MODE_CANDIDATE_MANIFEST_V1",
            "package_locator": "CODE_MODE_EVIDENCE_PACKAGE_V1",
            "core_locator": "CODE_MODE_EXECUTION_EVIDENCE_CORE_V1",
            "review_locator": "CODE_MODE_REVIEW_RECEIPT_V2",
            "gate_locator": "CODE_MODE_GATE_FACT_V1",
            "completion_plan_locator": "CODE_MODE_COMPLETION_PLAN_V1",
        }
        if "completion_plan_locator" not in resolved:
            expected_schema.pop("completion_plan_locator")
        bodies: dict[str, Mapping[str, Any]] = {}
        for role, schema in expected_schema.items():
            payload = resolved[role].get("payload")
            if not isinstance(payload, Mapping) or payload.get("schema") != schema:
                raise AuthorityError(role + " is not the expected typed fact")
            bodies[role] = payload
            body_hash = self._payload_content_hash(payload)
            if not isinstance(body_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", body_hash):
                raise AuthorityError(role + " is missing its typed payload hash")
            if body_hash != payload_self_hash(payload):
                raise AuthorityError(role + " content hash is inconsistent")

        request = bodies["request_locator"]
        candidate = bodies["candidate_locator"]
        package = bodies["package_locator"]
        core = bodies["core_locator"]
        review = bodies["review_locator"]
        gate = bodies["gate_locator"]
        plan = bodies.get("completion_plan_locator", {})
        # Every typed object in this authority decision must carry its own
        # authenticated identity.  ``None``/missing values are not a
        # wildcard: accepting them would let an otherwise valid CAS object
        # float between runs or generations.
        for role, body in bodies.items():
            for field in ("content_hash", "run_id", "generation"):
                if not isinstance(body.get(field), str) or not body.get(field):
                    raise AuthorityError(role + " is missing required " + field)
        # Candidate/plan payloads are immutable identities, while execution
        # facts must also carry the concrete CLI instance and attempt.  These
        # are required bindings, not optional metadata or wildcards.
        for role, body in bodies.items():
            if role not in {"candidate_locator", "completion_plan_locator"}:
                if not isinstance(body.get("session_instance_id"), str) or not body.get("session_instance_id"):
                    raise AuthorityError(role + " is missing session instance binding")
                if type(body.get("run_attempt")) is not int or body.get("run_attempt") < 1:
                    raise AuthorityError(role + " is missing strict run attempt binding")
        for role, body in (
            ("request", request), ("package", package), ("core", core),
            ("review", review), ("gate", gate),
        ):
            if not isinstance(body.get("session_id"), str) or not body.get("session_id"):
                raise AuthorityError(role + " is missing conversation session binding")
            if type(body.get("turn_index")) is not int or body.get("turn_index") < 0:
                raise AuthorityError(role + " is missing typed turn binding")
        for role, body in (
            ("candidate", candidate), ("package", package), ("core", core),
            ("review", review), ("gate", gate),
        ):
            for field in ("candidate_id", "tree_hash"):
                if not isinstance(body.get(field), str) or not body.get(field):
                    raise AuthorityError(role + " is missing required " + field)
        for role, body in bodies.items():
            if body.get("run_id") != run_id:
                raise AuthorityError(role + " belongs to another run")
            if body.get("generation") != generation:
                raise AuthorityError(role + " belongs to another generation")
        candidate_id = candidate.get("candidate_id")
        tree_hash = candidate.get("tree_hash")
        if not isinstance(candidate_id, str) or not candidate_id or not isinstance(tree_hash, str) or not tree_hash:
            raise AuthorityError("candidate identity is incomplete")
        # The launcher pins the executable source checkout independently of
        # the candidate inventory.  The latter's source_manifest_hash is a
        # candidate identity commitment (and may intentionally differ from
        # the launcher source-code manifest), so bind it across every
        # execution fact rather than conflating the two identities.
        candidate_source_manifest = candidate.get("source_manifest_hash")
        if not isinstance(candidate_source_manifest, str) or not candidate_source_manifest:
            raise AuthorityError("candidate source identity is incomplete")
        for role in ("package_locator",):
            if bodies[role].get("source_manifest_hash") != candidate_source_manifest:
                raise AuthorityError(role + " candidate source identity changed")
        machine_ref = package.get("machine_check_ref")
        expected_core_locators = (
            ("candidate_locator", locators.get("candidate_locator")),
            ("machine_check_locator", machine_ref),
            ("evidence_package_locator", locators.get("package_locator")),
            ("review_request_locator", locators.get("request_locator")),
        )
        for field, expected_reference in expected_core_locators:
            locator = core.get(field)
            if not isinstance(locator, Mapping) or locator.get("reference_id") != expected_reference:
                raise AuthorityError("core " + field + " is not bound to the reopened locator")
        for role, body in (("request", request), ("package", package), ("core", core), ("review", review), ("gate", gate)):
            if (
                not isinstance(body.get("candidate_id"), str)
                or not body.get("candidate_id")
                or not isinstance(body.get("tree_hash"), str)
                or not body.get("tree_hash")
                or body.get("candidate_id") != candidate_id
                or body.get("tree_hash") != tree_hash
            ):
                raise AuthorityError(role + " candidate binding changed")
        session_id = request.get("session_id")
        turn_index = request.get("turn_index")
        session_instance_id = request.get("session_instance_id")
        run_attempt = request.get("run_attempt")
        if not isinstance(session_id, str) or not session_id:
            raise AuthorityError("review request session binding is missing")
        if type(turn_index) is not int or turn_index < 0:
            raise AuthorityError("review request turn binding is missing")
        frames = snapshot if snapshot is not None else self._journal_snapshot()
        conversation_locator, _conversation_version = self._bound_conversation(
            "session/" + session_id,
            session_id=session_id,
            turn_index=turn_index,
            run_id=run_id,
            session_instance_id=session_instance_id,
            run_attempt=run_attempt,
            generation=generation,
            message_hash=request.get("conversation_message_hash"),
            snapshot=frames,
        )
        if conversation_locator != "session/" + session_id:
            raise AuthorityError("conversation session locator is not canonical")
        if review.get("session_id") != session_id or type(review.get("turn_index")) is not int:
            raise AuthorityError("reviewer session/turn binding changed")
        if review.get("turn_index") != turn_index:
            raise AuthorityError("reviewer turn binding changed")
        for role, body in bodies.items():
            if role in {"candidate_locator", "completion_plan_locator"}:
                continue
            if body.get("session_instance_id") != session_instance_id or body.get("run_attempt") != run_attempt:
                raise AuthorityError(role + " session instance or attempt changed")
        # The request must be the one durable producer fact for this current
        # run.  Reopening the CAS without this Journal fact would allow a
        # caller-created object to become an authority input.
        # Attempt identity is a Journal fact, not a value that can be
        # reconstructed from a self-consistent locator bundle.  Reopen the
        # complete authenticated chain before any plan/acceptance signature;
        # in particular, do not let an old authorization_ref become current
        # merely because all supplied CAS objects agree with one another.
        attempt_events = sorted(
            (
                event
                for frame in snapshot
                if frame.transaction.stream_id == f"run/{run_id}"
                for event in frame.transaction.events
                if isinstance(event.payload, Mapping)
                and event.payload.get("event_type") in {
                    "execution.authorization.bound",
                    "execution.authorization.attempt_advanced",
                }
                and event.payload.get("schema") in {
                    "SITINA_EXECUTION_AUTHORIZATION_V1",
                    "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1",
                }
            ),
            key=lambda event: (int(event.stream_version), int(event.position)),
        )
        if not attempt_events:
            raise AuthorityError("current authenticated execution attempt is missing")
        first_attempt = attempt_events[0].payload
        if (
            first_attempt.get("schema") != "SITINA_EXECUTION_AUTHORIZATION_V1"
            or first_attempt.get("event_type") != "execution.authorization.bound"
            or type(first_attempt.get("run_attempt")) is not int
            or first_attempt.get("run_attempt") != 1
        ):
            raise AuthorityError("execution attempt chain has no exact attempt-one root")
        attempt_identity_fields = (
            "session_instance_id", "session_id", "run_id", "generation", "workspace",
        )
        for event in attempt_events:
            payload = event.payload
            if any(payload.get(field) != first_attempt.get(field) for field in attempt_identity_fields):
                raise AuthorityError("execution attempt chain identity changed")
        latest_attempt = dict(first_attempt)
        latest_attempt_number = 1
        for event in attempt_events[1:]:
            payload = event.payload
            if (
                payload.get("schema") != "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1"
                or payload.get("event_type") != "execution.authorization.attempt_advanced"
                or type(payload.get("previous_run_attempt")) is not int
                or type(payload.get("run_attempt")) is not int
                or payload.get("previous_run_attempt") != latest_attempt_number
                or payload.get("run_attempt") != latest_attempt_number + 1
                or payload.get("previous_authorization_ref") != latest_attempt.get("authorization_ref")
                or not isinstance(payload.get("authorization_ref"), str)
                or payload.get("authorization_ref") == latest_attempt.get("authorization_ref")
            ):
                raise AuthorityError("execution attempt chain is not contiguous")
            latest_attempt = dict(payload)
            latest_attempt_number += 1
        if type(run_attempt) is not int or run_attempt != latest_attempt_number:
            raise AuthorityError("review facts do not use the authenticated latest attempt")
        if latest_attempt.get("session_instance_id") != session_instance_id:
            raise AuthorityError("review facts use another CLI session instance")
        if request.get("authorization_ref") != latest_attempt.get("authorization_ref"):
            raise AuthorityError("review request is not bound to the authenticated latest authorization")
        for role_name, fact_body in bodies.items():
            if role_name == "completion_plan_locator":
                continue
            if fact_body.get("authorization_ref") != latest_attempt.get("authorization_ref"):
                raise AuthorityError(role_name + " is not bound to the authenticated latest authorization")

        def exact_fact(
            role: str, reference: str, schema: str,
            expected_body: Mapping[str, Any] | None = None,
        ) -> Mapping[str, Any]:
            fact_body = expected_body if expected_body is not None else bodies[role]
            role_name = {
                "request_locator": "request", "package_locator": "package",
                "review_locator": "review", "machine_locator": "machine",
                "core_locator": "core",
            }.get(role, role.removesuffix("_locator"))
            producer = code_mode_producer_spec(role_name)
            fact_schema = str(producer["fact_schema"])
            expected_event_type = producer.get("event_type")
            if not isinstance(expected_event_type, str):
                expected_event_type = "protocol." + fact_schema.lower().removesuffix("_v1").replace("_", ".")
            expected_purpose = producer.get("purpose_class")
            role_matches = [
                event for frame in snapshot
                if frame.transaction.stream_id == f"run/{run_id}"
                for event in frame.transaction.events
                if isinstance(event.payload, Mapping)
                and event.event_type == expected_event_type
                and event.payload.get("schema") == fact_schema
                and (fact_schema != "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1" or event.payload.get("evidence_schema") == schema)
                and (expected_purpose is None or event.payload.get("purpose_class") == expected_purpose)
                and event.payload.get("run_id") == run_id
                and event.payload.get("session_instance_id") == session_instance_id
                and type(event.payload.get("run_attempt")) is int
                and event.payload.get("run_attempt") == run_attempt
            ]
            if len(role_matches) != 1:
                raise AuthorityError(role + " does not have exactly one authenticated current-attempt producer fact")
            event = role_matches[0]
            if (
                event.payload.get("reference_id") != reference
                or event.payload.get("content_hash") != fact_body.get("content_hash")
            ):
                raise AuthorityError(role + " producer fact locator or hash changed")
            refs = tuple(getattr(event, "object_refs", ()) or ())
            expected_refs = [reference]
            response_locator = fact_body.get("response_locator")
            if (
                role_name == "core"
                and isinstance(response_locator, Mapping)
                and isinstance(response_locator.get("reference_id"), str)
            ):
                expected_refs.append(str(response_locator["reference_id"]))
            if refs != tuple(sorted(set(expected_refs))):
                raise AuthorityError(role + " producer fact has incorrect object ownership")
            # The fact event is itself part of the authenticated Journal
            # transaction.  Requiring its canonical payload hash to agree
            # with the reopened object prevents a same-run, foreign producer
            # from hiding behind a matching locator string.
            if event.payload.get("reference_id") != reference:
                raise AuthorityError(role + " producer fact reference drifted")
            for field in (
                "session_instance_id", "session_id", "turn_index", "run_attempt",
                "generation", "candidate_id", "tree_hash",
            ):
                if field in fact_body and event.payload.get(field) != fact_body.get(field):
                    raise AuthorityError(role + " producer fact binding changed: " + field)
            return event.payload

        def exact_candidate_fact(reference: str, expected_body: Mapping[str, Any]) -> Mapping[str, Any]:
            """Reopen the dedicated candidate producer fact.

            Candidate manifests are not generic evidence receipts.  Keeping
            this matcher separate prevents a generic evidence event (or a
            caller-created object with a matching locator) from becoming the
            candidate identity used by the authority decision.
            """
            producer = code_mode_producer_spec("candidate")
            role_matches = [
                event for frame in snapshot
                if frame.transaction.stream_id == f"run/{run_id}"
                for event in frame.transaction.events
                if isinstance(event.payload, Mapping)
                and event.event_type == producer["event_type"]
                and event.payload.get("schema") == producer["fact_schema"]
                and event.payload.get("run_id") == run_id
                and event.payload.get("session_instance_id") == session_instance_id
                and type(event.payload.get("run_attempt")) is int
                and event.payload.get("run_attempt") == run_attempt
            ]
            if len(role_matches) != 1:
                raise AuthorityError("candidate does not have exactly one dedicated current-attempt producer fact")
            event = role_matches[0]
            if (
                event.payload.get("reference_id") != reference
                or event.payload.get("content_hash") != expected_body.get("content_hash")
            ):
                raise AuthorityError("candidate producer fact locator or hash changed")
            if tuple(getattr(event, "object_refs", ()) or ()) != (reference,):
                raise AuthorityError("candidate producer fact has incorrect object ownership")
            expected_fields = (
                "session_instance_id", "session_id", "turn_index", "run_attempt",
                "generation", "candidate_id", "tree_hash", "source_manifest_hash",
                "authorization_ref",
            )
            for field in expected_fields:
                expected = expected_body.get(field)
                actual = event.payload.get(field)
                if type(expected) is int:
                    if type(actual) is not int or actual != expected:
                        raise AuthorityError("candidate producer fact binding changed: " + field)
                elif not isinstance(expected, str) or not expected or actual != expected:
                    raise AuthorityError("candidate producer fact binding changed: " + field)
            return event.payload
        exact_fact("request_locator", locators["request_locator"], "CODE_MODE_REVIEW_REQUEST_V2")
        exact_fact("package_locator", locators["package_locator"], "CODE_MODE_EVIDENCE_PACKAGE_V1")
        exact_fact("review_locator", locators["review_locator"], "CODE_MODE_REVIEW_RECEIPT_V2")
        candidate_fact = exact_candidate_fact(locators["candidate_locator"], candidate)
        machine_ref = package.get("machine_check_ref")
        machine_hash = package.get("machine_check_hash")
        if not isinstance(machine_ref, str) or not isinstance(machine_hash, str):
            raise AuthorityError("package machine lineage is incomplete")
        machine_resolved = self._cas_locator(machine_ref, role="machine_locator")
        exact_fact(
            "machine_locator", machine_ref, "CODE_MODE_MACHINE_CHECK_RECEIPT_V1",
            expected_body=machine_resolved.get("payload")
            if isinstance(machine_resolved.get("payload"), Mapping) else None,
        )
        core_ref = core.get("reference_id")
        if not isinstance(core_ref, str):
            core_ref = locators.get("core_locator")
        exact_fact(
            "core_locator", str(core_ref), "CODE_MODE_EXECUTION_EVIDENCE_CORE_V1",
            expected_body=core,
        )
        # A TTY receipt is not usable merely because its MAC/summary is
        # correct.  The nonce consumption is a separate, durable same-run
        # fact.  Reopen the complete set before any host signature so a
        # missing, duplicate, foreign, or post-cancel receipt cannot become a
        # plan/acceptance input.
        tty_nonce = request.get("tty_nonce")
        if not isinstance(tty_nonce, str) or not tty_nonce:
            raise AuthorityError("review request has no TTY nonce")
        nonce_hash = hashlib.sha256(tty_nonce.encode("utf-8")).hexdigest()
        nonce_events = [
            event for frame in snapshot
            if frame.transaction.stream_id == f"run/{run_id}"
            for event in frame.transaction.events
            if isinstance(event.payload, Mapping)
            and event.payload.get("schema") == "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1"
            and event.payload.get("request_ref") == locators["request_locator"]
            and event.payload.get("request_hash") == request.get("content_hash")
            and event.payload.get("session_instance_id") == session_instance_id
            and event.payload.get("session_id") == session_id
            and type(event.payload.get("run_attempt")) is int
            and event.payload.get("run_attempt") == run_attempt
        ]
        if len(nonce_events) != 1:
            raise AuthorityError("TTY nonce consumption is not exactly one authenticated same-run fact")
        nonce_fact = nonce_events[0].payload
        if (
            nonce_fact.get("consumed") is not True
            or nonce_fact.get("nonce_hash") != nonce_hash
            or not isinstance(nonce_fact.get("consumption_id"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", nonce_fact.get("consumption_id", ""))
            or nonce_fact.get("session_instance_id") != session_instance_id
            or nonce_fact.get("session_id") != session_id
            or nonce_fact.get("run_attempt") != run_attempt
            or nonce_fact.get("turn_index") != turn_index
            or nonce_fact.get("candidate_id") != candidate_id
            or nonce_fact.get("tree_hash") != tree_hash
            or nonce_fact.get("generation") != generation
            or nonce_fact.get("run_id") != run_id
        ):
            raise AuthorityError("TTY nonce consumption binding changed")
        consumption_ref = nonce_fact.get("reference_id")
        if not isinstance(consumption_ref, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", consumption_ref):
            raise AuthorityError("TTY nonce consumption has no durable CAS mapping")
        consumption = self._cas_locator(consumption_ref, role="tty_consumption_locator")
        consumption_body = consumption.get("payload")
        if (
            not isinstance(consumption_body, Mapping)
            or consumption_body.get("schema") != "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1"
            or consumption_body.get("content_hash") != consumption.get("content_hash")
            or payload_self_hash(consumption_body) != consumption.get("content_hash")
            or consumption_body.get("nonce_hash") != nonce_hash
            or consumption_body.get("consumption_id") != nonce_fact.get("consumption_id")
            or consumption_body.get("request_ref") != locators["request_locator"]
            or consumption_body.get("request_hash") != request.get("content_hash")
            or consumption_body.get("session_instance_id") != session_instance_id
            or consumption_body.get("session_id") != session_id
            or consumption_body.get("run_attempt") != run_attempt
            or consumption_body.get("turn_index") != turn_index
            or consumption_body.get("candidate_id") != candidate_id
            or consumption_body.get("tree_hash") != tree_hash
            or consumption_body.get("generation") != generation
            or consumption_body.get("run_id") != run_id
            or consumption_body.get("consumed") is not True
        ):
            raise AuthorityError("TTY nonce consumption CAS proof is not bound to the current request")
        cancelled = [
            event for frame in snapshot
            if frame.transaction.stream_id == f"run/{run_id}"
            for event in frame.transaction.events
            if isinstance(event.payload, Mapping)
            and event.payload.get("schema") == "CODE_MODE_REVIEW_CANCELLED_V1"
            and event.payload.get("reference_id") == locators["request_locator"]
            and event.payload.get("content_hash") == request.get("content_hash")
        ]
        if cancelled:
            raise AuthorityError("TTY review request was cancelled")
        if request.get("evidence_package_ref") not in (None, locators["package_locator"]):
            raise AuthorityError("review request package binding changed")
        machine_ref = package.get("machine_check_ref")
        machine_hash = package.get("machine_check_hash")
        if not isinstance(machine_ref, str) or not isinstance(machine_hash, str):
            raise AuthorityError("package machine lineage is incomplete")
        machine = self._cas_locator(machine_ref, role="machine_locator")
        machine_body = machine["payload"]
        if (
            machine_body.get("schema") != "CODE_MODE_MACHINE_CHECK_RECEIPT_V1"
            or machine_body.get("content_hash") != machine_hash
            or machine_body.get("run_id") != run_id
            or machine_body.get("generation") != generation
            or machine_body.get("candidate_id") != candidate_id
            or machine_body.get("tree_hash") != tree_hash
            or machine_body.get("session_id") != session_id
            or type(machine_body.get("turn_index")) is not int
            or machine_body.get("turn_index") != turn_index
            or machine_body.get("source_manifest_hash") != candidate_source_manifest
        ):
            raise AuthorityError("package machine lineage does not match the current facts")
        # Recompute the machine/package admission from observed execution
        # facts.  A caller-created Gate-shaped CAS object is not evidence of
        # readiness, even when its content hash is self-consistent.
        machine_counts = ("failures", "errors", "skipped", "unexpected_successes")
        if (
            machine_body.get("status") != "MACHINE_CHECK_READY"
            or machine_body.get("execution_observed") is not True
            or type(machine_body.get("return_code")) is not int
            or machine_body.get("return_code") != 0
            or any(type(machine_body.get(field)) is not int or machine_body.get(field) != 0 for field in machine_counts)
            or not isinstance(machine_body.get("test_inventory"), list)
            or not machine_body.get("test_inventory")
        ):
            raise AuthorityError("machine receipt does not independently prove a passing test run")
        package_tester = package.get("tester")
        package_cleanup = package.get("cleanup")
        package_closing = package.get("closing_root")
        package_failures: list[str] = []
        if not isinstance(package_tester, Mapping):
            package_failures.append("tester")
        else:
            if package_tester.get("status") != "MACHINE_CHECK_READY":
                package_failures.append("tester.status")
            if package_tester.get("accepted") is not True:
                package_failures.append("tester.accepted")
            if package_tester.get("evidence_hash") != machine_body.get("test_evidence_hash"):
                package_failures.append("tester.evidence_hash")
        if not isinstance(package_cleanup, Mapping) or package_cleanup.get("observed") is not True:
            package_failures.append("cleanup")
        if not isinstance(package_closing, Mapping) or package_closing.get("sealed") is not True:
            package_failures.append("closing_root")
        if package.get("candidate_manifest_ref") != locators.get("candidate_locator"):
            package_failures.append("candidate_ref")
        if package.get("candidate_manifest_hash") != resolved["candidate_locator"].get("content_hash"):
            package_failures.append("candidate_hash")
        if package.get("diff_hash") != machine_body.get("diff_hash"):
            package_failures.append("diff_hash")
        if package.get("worktree_before_hash") != machine_body.get("worktree_before_hash"):
            package_failures.append("worktree_before_hash")
        if package.get("worktree_after_hash") != machine_body.get("worktree_after_hash"):
            package_failures.append("worktree_after_hash")
        if package_failures:
            raise AuthorityError("execution package does not independently prove the current run: " + ",".join(package_failures))
        gate_required = {
            "status": "CODE_MODE_READY", "gate_identity": "code-mode-acceptance-v1",
            "run_id": run_id, "generation": generation,
            "candidate_id": candidate_id, "tree_hash": tree_hash,
            "session_id": session_id, "turn_index": turn_index,
            "package_hash": package.get("content_hash"),
            "core_hash": core.get("content_hash"),
        }
        for field, expected in gate_required.items():
            actual = gate.get(field)
            if type(expected) is int:
                if type(actual) is not int or actual != expected:
                    raise AuthorityError("Gate binding is incomplete: " + field)
            elif actual != expected:
                raise AuthorityError("Gate binding is incomplete: " + field)
        if not isinstance(gate.get("issuer_identity"), str) or gate.get("issuer_identity") != "code-mode-gate-v1":
            raise AuthorityError("Gate issuer is not the pinned Code Mode verifier")
        if gate.get("authority_class") != "CODE_MODE_GATE_AUTHORITY":
            raise AuthorityError("Gate authority class is not authenticated")
        # The Gate currently has no independent signing key.  It is therefore
        # accepted only as a deterministic projection of the independently
        # reopened facts, with an exact content hash and no extra fields.  A
        # caller cannot turn a self-published READY mapping into authority by
        # merely making its fields internally consistent.
        expected_gate = code_mode_gate_projection(
            run_id=run_id, generation=generation, candidate_id=candidate_id,
            tree_hash=tree_hash, session_id=session_id, turn_index=turn_index,
            session_instance_id=str(session_instance_id), run_attempt=run_attempt,
            package_hash=str(package.get("content_hash") or ""),
            core_hash=str(core.get("content_hash") or ""),
            provider_profile=str(package.get("provider_profile") or ""),
            provider_model=str(package.get("provider_model") or ""),
            authorization_ref=str(latest_attempt.get("authorization_ref") or ""),
        )
        if dict(gate) != expected_gate:
            raise AuthorityError("Gate READY is not the exact controller fact projection")
        if review.get("decision") != "ACCEPT":
            raise AuthorityError("reviewer fact is not an ACCEPT")
        # This local session-level release has exactly one positive review
        # authority.  The headless producer remains an explicit pending
        # path; accepting its fields here would turn a caller-supplied or
        # fixture verdict into an authority input.
        if review.get("authority_class") != "TTY_REVIEW_AUTHORITY":
            raise AuthorityError("only a current TTY reviewer may authorize Code Mode")
        if not isinstance(review.get("reviewer_session_id"), str) or not review.get("reviewer_session_id"):
            raise AuthorityError("reviewer session identity is missing")
        if review.get("authority_class") == "INDEPENDENT_REVIEWER_AUTHORITY":
            for field in ("issuer_id", "issuer_signature", "producer_signature", "review_binding_hash"):
                if not isinstance(review.get(field), str) or not review.get(field):
                    raise AuthorityError("reviewer signature binding is incomplete")
            expected_issuer = self._reviewer_verification.get("issuer_id")
            mac_key_hex = self._reviewer_verification.get("mac_key_hex")
            producer_id = self._reviewer_verification.get("producer_id")
            producer_public_key = self._reviewer_verification.get("producer_public_key")
            if (
                not isinstance(expected_issuer, str) or review.get("issuer_id") != expected_issuer
                or not isinstance(mac_key_hex, str) or not isinstance(producer_id, str)
                or not isinstance(producer_public_key, str)
                or review.get("reviewer_id") != expected_issuer
                or review.get("reviewer_session_id") != expected_issuer
                or review.get("producer_issuer_id") != producer_id
                or review.get("producer_public_key") != producer_public_key
            ):
                raise AuthorityError("reviewer issuer or producer is not launcher-pinned")
            try:
                mac_key = bytes.fromhex(mac_key_hex)
                reviewer_unsigned = {
                    key: review[key] for key in (
                        "schema", "candidate_id", "tree_hash", "test_receipt_hash", "run_id",
                        "reviewer_id", "decision", "authority_class", "review_binding_hash",
                        "reviewer_session_id", "producer_issuer_id", "producer_public_key",
                        "producer_signature", "review_evidence_hash", "findings", "severity",
                        "verdict_decision", "issued_at", "expires_at", "issuer_id",
                    )
                }
                expected_signature = hmac.new(mac_key, _canonical(reviewer_unsigned), hashlib.sha256).hexdigest()
            except (ValueError, KeyError, TypeError) as error:
                raise AuthorityError("reviewer issuer signature cannot be verified") from error
            if not hmac.compare_digest(str(review.get("issuer_signature")), expected_signature):
                raise AuthorityError("reviewer issuer signature is invalid")
            review_binding = {
                "candidate_id": candidate_id,
                "tree_hash": tree_hash,
                "test_receipt_hash": review.get("test_receipt_hash"),
                "run_id": run_id,
                "expires_at": review.get("expires_at"),
                "issuer_id": expected_issuer,
            }
            if review.get("review_binding_hash") != hashlib.sha256(_canonical(review_binding)).hexdigest():
                raise AuthorityError("reviewer binding hash is invalid")
            if review.get("review_evidence_hash") != hashlib.sha256(
                _canonical({
                    "candidate_id": candidate_id, "tree_hash": tree_hash,
                    "test_receipt_hash": machine_hash,
                    "evidence_package_hash": package.get("content_hash"),
                    "run_id": run_id, "session_id": session_id,
                    "generation": generation,
                    "verifier_identity": package.get("verifier_identity"),
                    "command": list((package.get("tester") or {}).get("command") or []),
                    "command_hash": str((package.get("tester") or {}).get("command_hash") or ""),
                    "test_inventory": list((package.get("tester") or {}).get("test_inventory") or []),
                    "inventory_hash": str((package.get("tester") or {}).get("inventory_hash") or ""),
                    "test_ids": list((package.get("tester") or {}).get("test_ids") or []),
                    "interpreter": str((package.get("tester") or {}).get("interpreter") or ""),
                    "dependencies_hash": str((package.get("tester") or {}).get("dependencies_hash") or ""),
                    "cwd": str((package.get("tester") or {}).get("cwd") or ""),
                    "return_code": (package.get("tester") or {}).get("return_code"),
                    "failures": (package.get("tester") or {}).get("failures"),
                    "errors": (package.get("tester") or {}).get("errors"),
                    "skipped": (package.get("tester") or {}).get("skipped"),
                    "unexpected_successes": (package.get("tester") or {}).get("unexpected_successes"),
                    "output_summary": dict((package.get("tester") or {}).get("output_summary") or {}),
                    "review_request_ref": locators["request_locator"],
                    "evidence_package_ref": locators["package_locator"],
                    "machine_check_ref": machine_ref,
                    "machine_check_hash": machine_hash,
                    "worktree_before_hash": package.get("worktree_before_hash"),
                    "worktree_after_hash": package.get("worktree_after_hash"),
                    "diff_hash": package.get("diff_hash"),
                    "tool_ledger": dict(package.get("tool_ledger") or {}),
                    "tester": dict(package.get("tester") or {}),
                    "cleanup": dict(package.get("cleanup") or {}),
                    "closing_root": dict(package.get("closing_root") or {}),
                })
            ).hexdigest():
                raise AuthorityError("review evidence is not the reopened package projection")
        else:
            proof = review.get("tty_confirmation_proof")
            if not isinstance(proof, Mapping) or proof.get("schema") != "CODE_MODE_TTY_CONFIRMATION_V1":
                raise AuthorityError("TTY reviewer proof is missing: " + ",".join(sorted(str(key) for key in proof)) if isinstance(proof, Mapping) else "TTY reviewer proof is missing")
            if proof.get("request_ref") != locators["request_locator"] or proof.get("request_hash") != request.get("content_hash"):
                raise AuthorityError("TTY reviewer proof request binding changed")
            if proof.get("issuer_id") != review.get("reviewer_session_id"):
                raise AuthorityError("TTY reviewer issuer identity changed")
            if not isinstance(proof.get("issuer_signature"), str) or not proof.get("issuer_signature"):
                raise AuthorityError("TTY reviewer issuer signature is missing: " + ",".join(sorted(str(key) for key in proof)))
            expected_issuer = self._reviewer_verification.get("issuer_id")
            key_hex = self._reviewer_verification.get("mac_key_hex")
            if (
                not isinstance(expected_issuer, str)
                or expected_issuer != proof.get("issuer_id")
                or not isinstance(key_hex, str)
            ):
                raise AuthorityError("TTY reviewer issuer is not pinned by the launcher")
            try:
                mac_key = bytes.fromhex(key_hex)
            except ValueError as error:
                raise AuthorityError("TTY reviewer verification key is invalid") from error
            unsigned_proof = {key: value for key, value in proof.items() if key != "issuer_signature"}
            expected_signature = hmac.new(mac_key, _canonical(unsigned_proof), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(str(proof.get("issuer_signature")), expected_signature):
                raise AuthorityError("TTY reviewer issuer signature is invalid")
            proof_summary = {
                key: request.get(key)
                for key in ("candidate_id", "tree_hash", "run_id", "evidence_package_ref", "evidence_package_hash")
            }
            proof_summary["nonce"] = request.get("tty_nonce")
            proof_summary["expires_at"] = proof.get("expires_at")
            if (
                not isinstance(request.get("tty_nonce"), str)
                or proof.get("nonce_hash") != hashlib.sha256(request["tty_nonce"].encode("utf-8")).hexdigest()
                or proof.get("summary_hash") != hashlib.sha256(_canonical(proof_summary)).hexdigest()
            ):
                raise AuthorityError("TTY reviewer summary is not bound to the reopened request")
        confirmed_at = review.get("confirmed_at")
        issued_at = review.get("issued_at")
        expires_at = review.get("expires_at")
        now = int(time.time())
        if (
            type(issued_at) is not int or type(confirmed_at) is not int or type(expires_at) is not int
            or issued_at <= 0 or issued_at > confirmed_at or confirmed_at > expires_at
            or expires_at <= now or confirmed_at > now + 5
        ):
            raise AuthorityError("reviewer confirmation time is invalid")
        if plan.get("run_id") not in (None, run_id) or plan.get("generation") not in (None, generation):
            raise AuthorityError("completion plan binding changed")
        # A plan/acceptance request is authorized only against the exact
        # authenticated frame set that was reopened above.  The recheck is a
        # CAS boundary: callers cannot mutate the run or conversation between
        # fact validation and signing and have the host sign the stale view.
        if plan:
            operations = plan.get("operations")
            first_binding = (
                operations[0].get("logical_binding")
                if isinstance(operations, list) and operations and isinstance(operations[0], Mapping)
                else None
            )
            expected_snapshot_hash = plan.get("snapshot_hash") or (
                first_binding.get("snapshot_hash") if isinstance(first_binding, Mapping) else None
            )
            frontier = plan.get("snapshot_frontier") or (
                first_binding.get("snapshot_frontier") if isinstance(first_binding, Mapping) else None
            )
            if not isinstance(frontier, list) or not frontier:
                raise AuthorityError("completion plan has no authenticated snapshot frontier")
            expected_frontier = [
                (
                    str(item.get("stream_id")), int(item.get("last_stream_version")),
                    str(item.get("transaction_hash")),
                )
                for item in frontier
                if isinstance(item, Mapping)
                and isinstance(item.get("stream_id"), str)
                and type(item.get("last_stream_version")) is int
                and isinstance(item.get("transaction_hash"), str)
            ]
            if len(expected_frontier) != len(frontier):
                raise AuthorityError("completion plan snapshot frontier is malformed")
            plan_positions = [
                index for index, frame in enumerate(frames)
                if any(
                    isinstance(event.payload, Mapping)
                    and event.payload.get("schema") == "CODE_MODE_COMPLETION_PLAN_FACT_V1"
                    for event in frame.transaction.events
                )
            ]
            if len(plan_positions) != 1:
                raise AuthorityError("completion plan producer fact is not unique")
            if plan_positions[0] != len(frames) - 1:
                raise AuthorityError("authenticated snapshot has events after the published completion plan")
            plan_prefix = frames[: plan_positions[0]]
            actual_frontier = [
                (
                    str(frame.transaction.stream_id), int(frame.transaction.last_stream_version),
                    str(getattr(frame, "transaction_hash", "")),
                )
                for frame in plan_prefix
            ]
            if actual_frontier != expected_frontier:
                raise AuthorityError("completion plan authenticated snapshot frontier changed")
            actual_snapshot_hash = self._snapshot_hash(plan_prefix)
            if not isinstance(expected_snapshot_hash, str) or expected_snapshot_hash != actual_snapshot_hash:
                raise AuthorityError(
                    "completion plan authenticated snapshot changed: "
                    + str(expected_snapshot_hash) + " != " + actual_snapshot_hash
                )

    def _cas_locator(self, value: object, *, role: str) -> dict[str, Any]:
        if not isinstance(value, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", value):
            raise AuthorityError(role + " is not a durable CAS locator")
        try:
            cas = self._formal_cas()
            reference = cas.resolve_reference(value)
            proof = cas.verify_existing(reference)
            payload = parse_canonical_json(cas.open_verified(reference))
        except Exception as error:
            raise AuthorityError(role + " could not be reopened by the formal CAS verifier") from error
        expected_prefix = {
            "request_locator": "code-mode-review-request",
            "candidate_locator": "code-mode-candidate-manifest",
            "package_locator": "code-mode-execution-package",
            "core_locator": "code-mode-execution-evidence-core",
            "review_locator": "code-mode-evidence",
            "gate_locator": "code-mode-gate-fact",
            "completion_plan_locator": "code-mode-completion-plan",
            "tty_consumption_locator": "code-mode-tty-nonce-consumption",
            "terminal_stage_draft_locator": "code-mode-stage-draft-terminal",
            "root_stage_draft_locator": "code-mode-stage-draft-root",
            "conversation_stage_draft_locator": "code-mode-stage-draft-conversation",
        }.get(role)
        if expected_prefix and proof.purpose_class != expected_prefix:
            raise AuthorityError(role + " CAS purpose is not bound to its typed role")
        manifest = {
            "reference_id": proof.object_ref.reference_id,
            "proof_type": "published",
            "object_ref": {
                "object_id": proof.object_ref.object_id,
                "tenant_id": proof.object_ref.tenant_id,
                "plaintext_commitment": proof.object_ref.plaintext_commitment,
                "commitment_key_id": proof.object_ref.commitment_key_id,
                "profile": proof.object_ref.profile,
            },
            "object_path": proof.object_path,
            "core_header_hash": proof.core_header_hash,
            "envelope_id": proof.envelope_id,
            "purpose_class": proof.purpose_class,
        }
        if not isinstance(payload, Mapping):
            raise AuthorityError(role + " CAS payload is not a typed object")
        payload_hash = self._payload_content_hash(payload)
        if payload_hash is None:
            payload_hash = hashlib.sha256(_canonical(payload)).hexdigest()
        else:
            recomputed = payload_self_hash(payload)
            if payload_hash != recomputed:
                raise AuthorityError(role + " CAS payload self-hash is invalid")
        return {
            "reference_id": value, "object_hash": proof.object_ref.object_id,
            "payload_hash": payload_hash,
            "content_hash": payload_hash,
            "plaintext_commitment": proof.object_ref.plaintext_commitment,
            "proof_manifest": manifest, "payload": dict(payload),
        }

    def _locator_commitment(self, locators: Mapping[str, str]) -> tuple[str, str]:
        manifest = sorted(
            (self._cas_locator(reference, role=role)["proof_manifest"] for role, reference in locators.items()),
            key=lambda item: str(item["reference_id"]),
        )
        value = canonical_proof_manifest_hash(manifest)
        return hashlib.sha256(_canonical(manifest)).hexdigest(), value

    def _validate_stage_draft(
        self, draft: Mapping[str, Any], *, stage: str, run_id: str,
        generation: str, resolved: Mapping[str, Mapping[str, Any]],
        session_token: str | None = None,
    ) -> None:
        """Validate a stage draft against formal CAS facts before signing.

        The draft is an untrusted pre-acceptance input.  In particular, its
        hashes and proof list are not an authority decision.  Recompute the
        projection/hash and reopen every listed proof through LocalCAS so a
        caller cannot replace a body, purpose, object identity, or header
        while leaving a plausible-looking draft envelope behind.
        """
        payload = draft.get("payload")
        if not isinstance(payload, Mapping):
            raise AuthorityError(f"{stage} stage draft has no payload")
        projection = payload.get("event_projection")
        proofs = payload.get("proof_manifest")
        if (
            payload.get("schema") != "CODE_MODE_STAGE_DRAFT_V1"
            or payload.get("stage") != stage
            or payload.get("run_id") != run_id
            or payload.get("generation") != generation
            or not isinstance(projection, list) or not projection
            or not isinstance(proofs, list) or not proofs
        ):
            raise AuthorityError(f"{stage} stage draft schema/binding is invalid")
        projection_bytes = _canonical(list(projection))
        expected_projection_hash = hashlib.sha256(
            b"SITINA-CODE-MODE-ACTUAL-STAGE-V1\0" + projection_bytes
        ).hexdigest()
        if payload.get("event_projection_hash") != expected_projection_hash:
            raise AuthorityError(f"{stage} stage draft projection commitment is invalid")
        terminal_state = None
        if stage == "terminal" and isinstance(projection[-1], Mapping):
            terminal_payload = projection[-1].get("payload")
            if isinstance(terminal_payload, Mapping):
                terminal_state = terminal_payload.get("terminal_state")
        terminal_event = (
            "code-mode.terminal-success" if terminal_state == "SUCCEEDED"
            else "code-mode.terminal-failed" if terminal_state == "FAILED"
            else None
        )
        if stage == "terminal" and terminal_event is None:
            raise AuthorityError("terminal stage state is invalid")
        expected_event_types = {
            "terminal": [
                "run.closing", "protocol.terminal.negative.probe.rejected",
                "protocol.terminal.full.validation.accepted",
                "protocol.run.evidence.package.sealed", terminal_event,
            ],
            "root": ["code-mode.final-root"],
            "conversation": ["code-mode.conversation-completion"],
        }[stage]
        if len(projection) != len(expected_event_types) or [
            item.get("event_type") if isinstance(item, Mapping) else None
            for item in projection
        ] != expected_event_types:
            raise AuthorityError(f"{stage} stage event order is not the authenticated operation order")
        common = {
            "run_id": run_id,
            "generation": generation,
            "session_instance_id": resolved["request_locator"]["payload"].get("session_instance_id"),
            "session_id": resolved["request_locator"]["payload"].get("session_id"),
            "run_attempt": resolved["request_locator"]["payload"].get("run_attempt"),
            "candidate_id": resolved["candidate_locator"]["payload"].get("candidate_id"),
            "tree_hash": resolved["candidate_locator"]["payload"].get("tree_hash"),
        }
        request = resolved["request_locator"]["payload"]
        candidate = resolved["candidate_locator"]["payload"]
        gate = resolved["gate_locator"]["payload"]
        for item in projection:
            if not isinstance(item, Mapping) or set(item) != {"event_type", "schema", "payload", "object_refs"}:
                raise AuthorityError(f"{stage} stage draft event projection is not exact")
            body = item.get("payload")
            refs = item.get("object_refs")
            if not isinstance(body, Mapping) or not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
                raise AuthorityError(f"{stage} stage draft event body/ownership is invalid")
            if item.get("event_type") != body.get("event_type"):
                raise AuthorityError(f"{stage} stage draft event type is not body-bound")
            for field, expected in common.items():
                if field in body and body.get(field) != expected:
                    raise AuthorityError(f"{stage} stage draft binding changed: {field}")
            if "stage_body_tampered" in body:
                raise AuthorityError(f"{stage} stage draft contains an uncommitted field")
            if stage == "terminal" and item.get("event_type") in {
                "code-mode.terminal-success", "code-mode.terminal-failed",
            }:
                expected_schema = (
                    "CODE_MODE_TERMINAL_SUCCESS_V1"
                    if item.get("event_type") == "code-mode.terminal-success"
                    else "CODE_MODE_TERMINAL_FAILED_V1"
                )
                if body.get("schema") != expected_schema:
                    raise AuthorityError("Code Mode terminal event schema is not dedicated")
        normalized_proofs = []
        proof_payloads: list[Mapping[str, Any]] = []
        for proof in proofs:
            if not isinstance(proof, Mapping):
                raise AuthorityError(f"{stage} stage proof manifest entry is invalid")
            required = {
                "reference_id", "object_id", "tenant_id", "plaintext_commitment",
                "commitment_key_id", "profile", "proof_type", "purpose_class",
                "core_header_hash", "envelope_id", "rooted_transaction_hash",
            }
            if set(proof) != required or not isinstance(proof.get("reference_id"), str):
                raise AuthorityError(f"{stage} stage proof manifest is not exact")
            reopened = self._cas_locator(proof["reference_id"], role="stage_proof")
            proof_payloads.append(reopened["payload"])
            formal = reopened["proof_manifest"]
            object_ref = formal["object_ref"]
            expected = {
                "reference_id": formal["reference_id"],
                "object_id": object_ref["object_id"],
                "tenant_id": object_ref["tenant_id"],
                "plaintext_commitment": object_ref["plaintext_commitment"],
                "commitment_key_id": object_ref["commitment_key_id"],
                "profile": object_ref["profile"],
                "proof_type": formal["proof_type"],
                "purpose_class": formal["purpose_class"],
                "core_header_hash": formal["core_header_hash"],
                "envelope_id": formal["envelope_id"],
                "rooted_transaction_hash": formal.get("rooted_transaction_hash"),
            }
            if _canonical(dict(proof)) != _canonical(expected):
                raise AuthorityError(f"{stage} stage proof identity changed")
            normalized_proofs.append(expected)
        if payload.get("proof_manifest_hash") != canonical_proof_manifest_hash(normalized_proofs):
            raise AuthorityError(f"{stage} stage proof commitment is invalid")
        owned_refs = {str(item.get("reference_id")) for item in normalized_proofs}
        for item in projection:
            if any(ref not in owned_refs for ref in item.get("object_refs", [])):
                raise AuthorityError(f"{stage} stage event references an unowned proof")
        purpose_classes = {str(item.get("purpose_class") or "") for item in normalized_proofs}
        required_purpose = (
            "true-multi-agent-run-evidence"
            if stage == "terminal" else "code-mode-reviewed-terminal-receipt"
        )
        if purpose_classes != {required_purpose} or len(normalized_proofs) != 1:
            raise AuthorityError(f"{stage} stage proof roles are incomplete")
        receipt = None
        if stage in {"root", "conversation"}:
            receipt = next(
                (item for item in proof_payloads
                 if item.get("schema") == "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1"),
                None,
            )
            if not isinstance(receipt, Mapping):
                raise AuthorityError(f"{stage} stage has no authenticated final receipt source")
        if stage == "root":
            event_body = projection[0]["payload"]
            final_ref = next(
                item["reference_id"] for item in normalized_proofs
                if item.get("purpose_class") == required_purpose
            )
            expected_root_body = {
                "schema": "CODE_MODE_FINAL_ROOT_V2",
                "event_type": "code-mode.final-root",
                "run_id": run_id,
                "candidate_id": candidate.get("candidate_id"),
                "generation": generation,
                "review_request_ref": resolved["request_locator"]["reference_id"],
                "tty_review_receipt_ref": resolved["review_locator"]["reference_id"],
                "gate_status": gate.get("status"),
                "authenticated_seal": True,
                "final_receipt_ref": final_ref,
                "final_receipt_hash": receipt.get("content_hash"),
                "terminal_event_id": "logical:terminal",
                "terminal_event_hash": "logical:terminal",
                "completion_plan_ref": "logical:completion-plan",
                "completion_plan_hash": "logical:completion-plan",
                "seal_command_id": "logical:final-root",
            }
            if _canonical(dict(event_body)) != _canonical(expected_root_body):
                raise AuthorityError("root stage body is not the exact host-derived projection")
            binding_fields = (
                "run_id", "session_id", "turn_index", "candidate_id", "tree_hash",
                "generation", "review_request_ref", "tty_review_receipt_ref",
                "gate_status", "final_receipt_ref", "final_receipt_hash",
            )
            for field in binding_fields:
                expected_value = (
                    receipt.get("reviewed_terminal_receipt_ref")
                    if field == "final_receipt_ref" else receipt.get(field)
                )
                if field == "final_receipt_ref":
                    expected_value = next(
                        (entry["reference_id"] for entry in normalized_proofs
                         if entry.get("purpose_class") == required_purpose),
                        None,
                    )
                elif field == "final_receipt_hash":
                    expected_value = receipt.get("content_hash")
                if field in event_body and expected_value is not None and event_body.get(field) != expected_value:
                    raise AuthorityError(f"{stage} stage body is not derived from its final receipt: {field}")
        if stage == "terminal":
            evidence = next(
                (item for item in proof_payloads if item.get("schema") == "CODE_MODE_TERMINAL_EVIDENCE_V1"),
                None,
            )
            if not isinstance(evidence, Mapping):
                raise AuthorityError("terminal stage has no authenticated evidence source")
            terminal_projection = evidence.get("code_mode_terminal_projection")
            terminal_body = projection[-1]["payload"]
            if not isinstance(terminal_projection, Mapping):
                raise AuthorityError("terminal evidence has no complete terminal projection")
            for field in ("run_id", "candidate_id", "tree_hash", "generation", "execution_core_ref", "execution_core_hash"):
                expected_value = terminal_projection.get(field)
                if field in terminal_body and expected_value is not None and terminal_body.get(field) != expected_value:
                    raise AuthorityError("terminal body is not derived from authenticated terminal evidence: " + field)
            evidence_ref = next(
                item["reference_id"] for item in normalized_proofs
                if item.get("purpose_class") == required_purpose
            )

            # Construct the complete five-event semantic projection from the
            # reopened evidence.  Event payloads and their ownership refs are
            # separate commitments: ``object_refs`` is never a payload key.
            # This is intentionally a single canonical comparison, rather
            # than a collection of permissive field checks.
            closing_body = projection[0]["payload"]
            closing_schema = closing_body.get("schema")
            if closing_schema == "RUN_CLOSING_RESUMED_V1":
                expected_closing = {
                    "schema": "RUN_CLOSING_RESUMED_V1",
                    "event_type": "run.closing",
                    "run_id": run_id,
                    "state": "CLOSING",
                    "stream_version": evidence.get("run_stream_frontier", {}).get("stream_version"),
                    "admission_generation": evidence.get("admission_generation"),
                    "closing_reentered": False,
                }
                if (
                    type(expected_closing["stream_version"]) is not int
                    or type(expected_closing["admission_generation"]) is not int
                    or expected_closing["stream_version"] < 0
                    or expected_closing["admission_generation"] < 1
                ):
                    raise AuthorityError("terminal closing frontier is not an authenticated integer")
            elif closing_schema == "RUN_CLOSING_BEGAN_V1":
                expected_closing = {
                    "schema": "RUN_CLOSING_BEGAN_V1",
                    "event_type": "run.closing",
                    "run_id": run_id,
                    "admission_generation": evidence.get("admission_generation"),
                }
            else:
                raise AuthorityError("terminal closing projection has an unknown authenticated schema")
            if evidence.get("admission_generation") is None:
                # A missing generation is not an acceptable source of truth;
                # do not turn the old self-reported body into evidence.
                raise AuthorityError("terminal evidence lacks admission generation")

            negative_blocker_ref = domain_hash(
                "TRUE_MULTI_AGENT_TERMINAL_NEGATIVE_BLOCKER",
                _canonical({"run": run_id}),
            )
            negative_reason = "Projection is not even a terminal candidate"
            expected_negative = {
                "schema": "TERMINAL_NEGATIVE_PROBE_REJECTED_V1",
                "event_type": "protocol.terminal.negative.probe.rejected",
                "run_id": run_id,
                "blocker_kind": BlockerKind.PROTOCOL.value,
                "blocker_ref": negative_blocker_ref,
                "terminal_committed": False,
                "reason_hash": hashlib.sha256(negative_reason.encode("utf-8")).hexdigest(),
            }
            obligations = evidence.get("obligations")
            if not isinstance(obligations, Mapping):
                raise AuthorityError("terminal evidence obligations are not authenticated")
            obligations_ref = domain_hash(
                "TRUE_MULTI_AGENT_REQUIRED_OBLIGATIONS_COMPLETE",
                _canonical({"run": run_id, "obligations": sorted(obligations)}),
            )
            decision = evidence.get("terminal_decision")
            if not isinstance(decision, Mapping):
                raise AuthorityError("terminal evidence decision is missing")
            expected_validation = {
                "schema": "TERMINAL_FULL_VALIDATION_ACCEPTED_V1",
                "event_type": "protocol.terminal.full.validation.accepted",
                "run_id": run_id,
                "projection_source_position": terminal_projection.get("frozen_frontier_position"),
                "projection_candidate": True,
                "authoritative_blocker_counts": {kind.value: 0 for kind in BlockerKind},
                "required_obligations_complete_ref": obligations_ref,
                "failure_refs": [],
                "decision": dict(decision),
            }
            if expected_validation["projection_source_position"] is None:
                raise AuthorityError("terminal evidence lacks authenticated source frontier")
            if type(expected_validation["projection_source_position"]) is not int or expected_validation["projection_source_position"] < 0:
                raise AuthorityError("terminal validation source frontier is not an authenticated integer")
            # The terminal operation is a five-event transaction, not a
            # terminal-event label.  These projections are reconstructed
            # from the authenticated evidence source and the fixed terminal
            # protocol.  Reject additions/substitutions in the four
            # predecessor bodies before the host signs the stage.
            call_ids = [item.get("call_id") for item in evidence.get("calls", []) if isinstance(item, Mapping)]
            recovery_ids = [item.get("call_id") for item in evidence.get("provider_recovery_attempts", []) if isinstance(item, Mapping)]
            failed_receipts = evidence.get("failed_provider_transport_receipts", [])
            failed_ids_claimed = evidence.get("failed_provider_call_ids", [])
            if failed_receipts is None:
                failed_receipts = []
            if failed_ids_claimed is None:
                failed_ids_claimed = []
            if not isinstance(failed_receipts, list) or not isinstance(failed_ids_claimed, list):
                raise AuthorityError("terminal evidence failed Provider receipt projection is malformed")
            if any(not isinstance(item, str) or not item for item in call_ids + recovery_ids):
                raise AuthorityError("terminal evidence provider call identity is malformed")
            if any(not isinstance(item, str) or not item for item in failed_ids_claimed):
                raise AuthorityError("terminal evidence failed Provider call identity is malformed")
            if len(set(failed_ids_claimed)) != len(failed_ids_claimed):
                raise AuthorityError("terminal evidence failed Provider call identity is duplicated")
            if failed_receipts and not isinstance(session_token, str):
                raise AuthorityError("terminal evidence failed Provider receipts have no host session binding")
            session_receipts = self._transport.get(session_token, []) if isinstance(session_token, str) else []
            if not isinstance(session_receipts, list):
                raise AuthorityError("host transport ledger is invalid")
            derived_failed_ids: list[str] = []
            seen_failure_identities: set[str] = set()
            for raw_receipt in failed_receipts:
                if not isinstance(raw_receipt, Mapping):
                    raise AuthorityError("terminal evidence failed Provider receipt is not a mapping")
                receipt = dict(raw_receipt)
                if receipt.get("schema") != "CODE_MODE_PROVIDER_TRANSPORT_FAILURE_RECEIPT_V1":
                    raise AuthorityError("terminal evidence failed Provider receipt schema is invalid")
                provider_call_id = receipt.get("provider_call_id")
                receipt_run_id = receipt.get("run_id")
                if not isinstance(provider_call_id, str) or not provider_call_id:
                    raise AuthorityError("terminal evidence failed Provider receipt has no call identity")
                if receipt_run_id != run_id and not (
                    isinstance(receipt_run_id, str)
                    and receipt_run_id.startswith(f"forge-exec-{run_id}-")
                ):
                    raise AuthorityError("terminal evidence failed Provider receipt run is outside the current lineage")
                failure_identity = receipt.get("failure_identity")
                if not isinstance(failure_identity, str) or not failure_identity:
                    raise AuthorityError("terminal evidence failed Provider receipt identity is missing")
                if failure_identity in seen_failure_identities:
                    raise AuthorityError("terminal evidence failed Provider receipt is duplicated")
                seen_failure_identities.add(failure_identity)
                receipt_hash = receipt.get("receipt_hash")
                expected_receipt_hash = _hash({
                    key: value for key, value in receipt.items() if key != "receipt_hash"
                })
                if receipt_hash != expected_receipt_hash:
                    raise AuthorityError("terminal evidence failed Provider receipt hash is invalid")
                if (
                    not isinstance(receipt.get("issuer_id"), str)
                    or receipt.get("issuer_id") != self.issuer_id
                    or not isinstance(receipt.get("issuer_signature"), str)
                    or not receipt.get("issuer_signature")
                    or self._mac({
                        key: value for key, value in receipt.items()
                        if key not in {"issuer_signature", "receipt_hash"}
                    }) != receipt.get("issuer_signature")
                ):
                    raise AuthorityError("terminal evidence failed Provider receipt signature is invalid")
                if (
                    receipt.get("token_usage") is not None
                    or receipt.get("usage_status") != "unknown"
                    or receipt.get("usage_settled") is not False
                    or receipt.get("outcome_state") not in {"FAILED_CONFIRMED", "OUTCOME_UNKNOWN"}
                    or receipt.get("settlement_state") not in {"SETTLED", "RECONCILING"}
                ):
                    raise AuthorityError("terminal evidence failed Provider receipt usage/outcome is invalid")
                if not any(dict(item) == receipt for item in session_receipts if isinstance(item, Mapping)):
                    raise AuthorityError("terminal evidence failed Provider receipt is not in the current host ledger")
                if provider_call_id not in derived_failed_ids:
                    derived_failed_ids.append(provider_call_id)
            if failed_ids_claimed != derived_failed_ids:
                raise AuthorityError("terminal evidence failed Provider IDs do not match host receipts")
            provider_ids: list[str] = []
            for provider_call_id in call_ids + failed_ids_claimed:
                if provider_call_id not in provider_ids:
                    provider_ids.append(provider_call_id)
            expected_sealed = {
                "schema": "RUN_EVIDENCE_PACKAGE_SEALED_V1",
                "event_type": "protocol.run.evidence.package.sealed",
                "run_id": run_id,
                "evidence_package_ref": evidence_ref,
                "evidence_package_hash": evidence.get("content_hash"),
                "provider_call_ids": provider_ids,
                "provider_recovery_call_ids": recovery_ids,
            }
            sealed_refs = [evidence_ref]

            calls = evidence.get("calls")
            protocols = evidence.get("protocol_graph")
            if not isinstance(calls, list) or not isinstance(protocols, list):
                raise AuthorityError("terminal evidence calls/protocol graph are not authenticated")
            terminal_binding = evidence.get("code_mode_terminal_binding")
            if not isinstance(terminal_binding, Mapping):
                raise AuthorityError("terminal evidence lacks its complete Code Mode binding")
            terminal_binding = dict(terminal_binding)
            for field, value in (
                ("completion_plan_ref", "logical:completion-plan"),
                ("completion_plan_hash", "logical:completion-plan"),
            ):
                if field in terminal_binding:
                    terminal_binding[field] = value
            terminal_state = terminal_projection.get("terminal_state")
            if terminal_state not in {"SUCCEEDED", "FAILED"}:
                raise AuthorityError("terminal evidence state is invalid")
            expected_terminal_event = (
                ("CODE_MODE_TERMINAL_SUCCESS_V1", "code-mode.terminal-success")
                if terminal_state == "SUCCEEDED"
                else ("CODE_MODE_TERMINAL_FAILED_V1", "code-mode.terminal-failed")
            )
            expected_terminal = {
                "schema": expected_terminal_event[0],
                "event_type": expected_terminal_event[1],
                "run_id": run_id,
                "status": "terminal",
                "required_obligations_open": 0,
                "terminal_state": terminal_state,
                "terminal_command_id": decision.get("command_id"),
                "terminal_request_hash": decision.get("request_hash"),
                "authoritative_fact_hash": decision.get("authoritative_fact_hash"),
                "evidence_package_ref": evidence_ref,
                "evidence_package_hash": evidence.get("content_hash"),
                "called_agents": sorted(evidence.get("called_agents") or []),
                "selected_agents": sorted(evidence.get("selected_agents") or []),
                "provider_call_count": evidence.get("provider_call_count"),
                "provider_physical_send_count": evidence.get("provider_physical_send_count"),
                "provider_retry_count": sum(int(item.get("retry_count", 0) or 0) for item in calls if isinstance(item, Mapping)) + int(evidence.get("provider_retry_count", 0) or 0),
                "provider_fallback_count": sum(int(item.get("fallback_count", 0) or 0) for item in calls if isinstance(item, Mapping)) + int(evidence.get("provider_fallback_count", 0) or 0),
                "provider_unsettled_usage_count": evidence.get("provider_unsettled_usage_count"),
                "negotiation_protocol_count": sum(item.get("protocol_kind") == "debate" for item in protocols if isinstance(item, Mapping)),
                "handoff_protocol_count": sum(item.get("protocol_kind") == "handoff" for item in protocols if isinstance(item, Mapping)),
                "external_mutation_count": int((evidence.get("execution_result") or {}).get("external_mutation_count", 0) or 0),
                "legacy_read_count": evidence.get("legacy_read_count"),
                "acceptance_runtime_read_count": evidence.get("acceptance_runtime_read_count"),
                "user_response_hash": evidence.get("user_response_hash"),
                "code_mode_terminal_binding": terminal_binding,
            }
            expected_payloads = [
                expected_closing, expected_negative, expected_validation,
                expected_sealed, expected_terminal,
            ]
            expected_refs = [[], [], [], sealed_refs, sealed_refs]
            for index, (item, expected_payload, refs) in enumerate(zip(projection, expected_payloads, expected_refs)):
                if _canonical(dict(item.get("payload") or {})) != _canonical(expected_payload):
                    raise AuthorityError(f"terminal event {index} is not the exact host-derived projection")
                if item.get("object_refs") != refs:
                    raise AuthorityError(f"terminal event {index} proof ownership is not exact")
            return
        if stage == "conversation":
            event_body = projection[0]["payload"]
            final_ref = normalized_proofs[0]["reference_id"]
            expected_conversation_body = {
                "schema": "CODE_MODE_CONVERSATION_COMPLETION_V1",
                "event_type": "code-mode.conversation-completion",
                "run_id": run_id,
                "session_id": request.get("session_id"),
                "turn_index": request.get("turn_index"),
                "assistant_message_id": f"{request.get('session_id')}-assistant-{request.get('turn_index')}",
                "response_hash": receipt.get("user_response_hash"),
                "final_receipt_ref": final_ref,
                "final_receipt_hash": receipt.get("content_hash"),
                "completion_plan_ref": "logical:completion-plan",
                "completion_plan_hash": "logical:completion-plan",
            }
            if _canonical(dict(event_body)) != _canonical(expected_conversation_body):
                raise AuthorityError("conversation stage body is not the exact host-derived projection")

    @staticmethod
    def _acceptance_event_commitment(
        *, run_id: str, generation: str, locators: Mapping[str, str], resolved: Mapping[str, Mapping[str, Any]],
    ) -> str:
        """Commit the complete stable acceptance binding, not schema names.

        Dynamic Journal coordinates and signatures are assigned during append;
        every other acceptance field is projected from the typed CAS facts
        and durable locators.  LocalJournal uses this exact projection when it
        validates the actual pair, so extra or substituted fields cannot hide
        behind an object-id-only digest.
        """
        def body(role: str) -> Mapping[str, Any]:
            value = resolved[role].get("payload")
            if not isinstance(value, Mapping):
                raise AuthorityError(role + " payload is unavailable")
            return value
        request = body("request_locator")
        candidate = body("candidate_locator")
        package = body("package_locator")
        review = body("review_locator")
        gate = body("gate_locator")
        plan = body("completion_plan_locator")
        reviewer_event = {
            "schema": "CODE_MODE_FINAL_REVIEWER_FACT_V1",
            "event_type": "code-mode.final-reviewer-fact",
            "run_id": run_id,
            "session_id": request.get("session_id"),
            "candidate_id": candidate.get("candidate_id"),
            "tree_hash": candidate.get("tree_hash"),
            "generation": generation,
            "verifier_identity": package.get("verifier_identity"),
            "package_ref": locators["package_locator"],
            "package_hash": package.get("content_hash"),
            "request_ref": locators["request_locator"],
            "request_hash": request.get("content_hash"),
            "review_receipt_ref": locators["review_locator"],
            "review_receipt_hash": review.get("content_hash"),
            "authority_class": review.get("authority_class"),
            "issuer_identity": review.get("issuer_identity"),
            "reviewer_session_id": review.get("reviewer_session_id"),
            "decision": review.get("decision"),
            "gate_status": gate.get("status"),
            "gate_identity": gate.get("gate_identity"),
            "accepted_at": review.get("confirmed_at"),
            "turn_index": request.get("turn_index"),
            "_object_refs": sorted({locators["candidate_locator"], locators["package_locator"], locators["core_locator"], locators["review_locator"], locators["gate_locator"]}),
            "finalization_transaction": True,
        }
        accepted_event = {
            "schema": "CODE_MODE_REVIEW_ACCEPTED_V1",
            "event_type": "run.review-accepted",
            "run_id": run_id,
            "session_id": request.get("session_id"),
            "turn_index": request.get("turn_index"),
            "request_ref": locators["request_locator"],
            "request_hash": request.get("content_hash"),
            "package_ref": locators["package_locator"],
            "review_receipt_ref": locators["review_locator"],
            "review_receipt_hash": review.get("content_hash"),
            "gate_status": gate.get("status"),
            "gate_identity": gate.get("gate_identity"),
            "accepted_at": review.get("confirmed_at"),
            "completion_plan_ref": locators["completion_plan_locator"],
            # The event binds the plan's canonical body hash; the envelope's
            # plan commitment separately binds the durable CAS object hash.
            "completion_plan_hash": plan.get("content_hash"),
            "finalization_transaction": True,
            "_object_refs": sorted({locators["request_locator"], locators["completion_plan_locator"]}),
        }
        return acceptance_event_projection_hash([reviewer_event, accepted_event])

    def _load_profile_paths(self, profile_paths: object) -> None:
        """Load profile secrets only inside the authority process.

        The parent sends an opaque, exact path reference; it never reads or
        serializes the credential.  The host retains the token in memory only
        and exposes a redacted profile summary over IPC.
        """
        if not isinstance(profile_paths, Mapping):
            return
        for name, raw_path in profile_paths.items():
            profile_name = str(name or "").strip()
            path = Path(str(raw_path or "")).expanduser()
            try:
                info = path.lstat()
                if (
                    path.name.endswith(".template")
                    or not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o600
                ):
                    continue
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError):
                continue
            values: dict[str, str] = {}
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key.removeprefix("export ").strip()] = value.strip().strip("'\"")
            token = (
                values.get("SITINA_PROVIDER_AUTH_TOKEN")
                or values.get("ANTHROPIC_AUTH_TOKEN")
                or values.get("OPENAI_API_KEY")
                or values.get("DEEPSEEK_API_KEY")
                or ""
            )
            token_ref = (
                values.get("SITINA_PROVIDER_AUTH_TOKEN_REF")
                or values.get("ANTHROPIC_AUTH_TOKEN_REF")
                or values.get("OPENAI_API_KEY_REF")
                or values.get("DEEPSEEK_API_KEY_REF")
                or ""
            )
            if token_ref:
                try:
                    service, account = ProfileLoader._parse_keychain_reference(token_ref)
                    raw_token = SecurityFrameworkKeychainBackend().get(service, account)
                    if raw_token is not None:
                        token = raw_token.decode("utf-8").strip()
                except Exception:
                    # A profile with an unavailable or malformed keychain
                    # reference is not installed into the host registry.
                    token = ""
            base_url = (
                values.get("SITINA_PROVIDER_BASE_URL")
                or values.get("ANTHROPIC_BASE_URL")
                or values.get("OPENAI_BASE_URL")
                or values.get("DEEPSEEK_BASE_URL")
                or ""
            ).rstrip("/")
            model = (
                values.get("SITINA_PROVIDER_MODEL")
                or values.get("ANTHROPIC_MODEL")
                or values.get("OPENAI_MODEL")
                or values.get("DEEPSEEK_MODEL")
                or ""
            )
            explicit_protocol = (
                values.get("SITINA_PROVIDER_WIRE_PROTOCOL")
                or values.get("WIRE_PROTOCOL")
                or values.get("ANTHROPIC_WIRE_PROTOCOL")
                or values.get("OPENAI_WIRE_PROTOCOL")
                or ""
            )
            try:
                protocol = infer_wire_protocol(profile_name, base_url, explicit_protocol or None)
            except Exception:
                continue
            raw_hosts = values.get("SITINA_PROVIDER_ALLOWED_ENDPOINT_HOSTS") or values.get("SITINA_PROVIDER_ENDPOINT_HOSTS") or ""
            allowed_hosts = sorted({item.strip().casefold() for item in raw_hosts.split(",") if item.strip()})
            raw_capabilities = values.get("SITINA_PROVIDER_ADAPTER_CAPABILITIES") or ""
            capabilities = sorted({item.strip() for item in raw_capabilities.split(",") if item.strip()})
            if profile_name and token and base_url and model:
                self._profiles[profile_name] = {
                    "name": profile_name,
                    "base_url": base_url,
                    "auth_token": token,
                    "model": model,
                    "wire_protocol": protocol,
                    "adapter_capabilities": sorted(
                        provider_adapter_capabilities(profile_name, base_url, capabilities)
                    ),
                    "allowed_endpoint_hosts": allowed_hosts,
                }

    def _mac(self, body: Mapping[str, Any]) -> str:
        return hmac.new(self._binding_mac_key, _canonical(body), hashlib.sha256).hexdigest()

    def _signed(self, body: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(body)
        result["issuer_id"] = self.issuer_id
        result["issuer_signature"] = self._mac(result)
        return result

    def _session(self, token: object) -> dict[str, Any]:
        if not isinstance(token, str) or not isinstance(self._sessions.get(token), dict):
            raise AuthorityError("broker session is invalid")
        return self._sessions[token]

    def dispatch(self, request: Mapping[str, Any]) -> dict[str, Any]:
        method = request.get("method")
        if method == "hello":
            with open(__file__, "rb") as host_file:
                host_code_identity = hashlib.sha256(host_file.read()).hexdigest()
            identity = {
                "issuer_id": self.issuer_id, "pid": os.getpid(), "parent_pid": os.getppid(),
                "session_instance_id": self._session_instance_id,
                "parent_executable": os.path.realpath(sys.executable),
                "host_entrypoint": os.path.realpath(__file__),
                "host_code_identity": host_code_identity,
                "protocol": "CODE_MODE_HOST_IPC_V2",
                "trust_scope": "same-user-cli-parent-child-v1",
                "authority_class": "CODE_MODE_CONTROLLER_SESSION",
                "authority_key_id": self._authority_key_id,
                "authority_public_key_hex": self._authority_public_key.hex(),
            }
            identity["challenge_proof"] = hmac.new(self._challenge_secret, _canonical(identity), hashlib.sha256).hexdigest()
            return identity
        session_token = request.get("session")
        if method == "bind":
            # Binding is derived exclusively from the launcher-owned
            # bootstrap.  A client cannot submit replacement state/journal or
            # workspace identities after attestation.
            if set(request) != {"method", "controller_capability_public_key"}:
                raise AuthorityError("runtime bind accepts no caller identity fields")
            controller_capability_public_key = str(request.get("controller_capability_public_key") or "")
            try:
                controller_capability_public_key_bytes = bytes.fromhex(controller_capability_public_key)
            except ValueError as error:
                raise AuthorityError("controller capability public key is invalid") from error
            if len(controller_capability_public_key_bytes) != 32:
                raise AuthorityError("controller capability public key is invalid")
            if controller_capability_public_key_bytes != self._bootstrap_controller_capability_public_key:
                raise AuthorityError("controller capability public key is not launcher-pinned")
            values = (
                str(self._bootstrap_runtime_state_identity),
                str(self._bootstrap_runtime_journal_id),
                self._state_root_identity,
            )
            session_token = secrets.token_urlsafe(32)
            transport_capability = secrets.token_urlsafe(32)
            binding = self._signed({
                "schema": "CODE_MODE_BROKER_RUNTIME_BINDING_V1",
                "runtime_state_identity": values[0], "runtime_journal_id": values[1],
                "runtime_root_identity": values[2], "broker_pid": os.getpid(),
                "session_instance_id": self._session_instance_id,
                "workspace": str(self._workspace), "workspace_identity": self._workspace_identity,
                "source_root": str(self._source_root),
                "runtime_authority_handle_hash": hashlib.sha256(session_token.encode()).hexdigest(),
            })
            self._sessions[session_token] = {
                "binding": binding, "transport_capability": transport_capability,
                "controller_capability_public_key": controller_capability_public_key_bytes,
                "live_capabilities": {},
                "authorization_domains": {},
                "root_fsm_state": "EXPECT_DISCOVERY",
                "root_phase_history": [],
                "last_pre_provider_identity": None,
            }
            self._transport[session_token] = []
            return {"session": session_token, "binding": binding, "transport_capability": transport_capability}
        session = self._session(session_token)
        if method == "binding":
            return dict(session["binding"])
        if method == "profile_summary":
            profile_name = str(request.get("profile") or "")
            profile = self._profiles.get(profile_name)
            if not isinstance(profile, Mapping):
                raise AuthorityError("host has no authorized provider profile")
            return {
                "name": profile_name,
                "base_url": str(profile.get("base_url") or ""),
                "model": str(profile.get("model") or ""),
                "wire_protocol": _profile_wire_protocol(profile),
                "adapter_capabilities": sorted(_profile_adapter_capabilities(profile)),
                "allowed_endpoint_hosts": sorted(
                    str(item).casefold()
                    for item in (profile.get("allowed_endpoint_hosts") or ())
                    if isinstance(item, str) and item.strip()
                ),
            }
        if method == "register_live_capability":
            capability = request.get("capability")
            if not isinstance(capability, Mapping):
                raise AuthorityError("live capability projection is invalid")
            required = {
                "schema", "live_opt_in", "purpose", "scope", "session_id", "cli_session_instance_id", "run_id",
                "issued_at", "expires_at", "nonce", "issuer_public_key", "issuer_signature",
            }
            if set(capability) != required or capability.get("schema") != "SITINA_SESSION_LIVE_CAPABILITY_V1":
                raise AuthorityError("live capability projection is not exact")
            if capability.get("scope") != "current-session" or capability.get("live_opt_in") is not True:
                raise AuthorityError("live capability scope is invalid")
            if capability.get("purpose") not in CODE_MODE_LIVE_CAPABILITY_PURPOSES:
                raise AuthorityError("live capability purpose is not authorized")
            if capability.get("cli_session_instance_id") != session["binding"].get("session_instance_id"):
                raise AuthorityError("live capability CLI session identity is not bound to this host session")
            if type(capability.get("issued_at")) is not int or type(capability.get("expires_at")) is not int:
                raise AuthorityError("live capability lifetime is invalid")
            public_key_hex = capability.get("issuer_public_key")
            signature_hex = capability.get("issuer_signature")
            if (not isinstance(public_key_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", public_key_hex)
                    or not isinstance(signature_hex, str) or not re.fullmatch(r"[0-9a-f]{128}", signature_hex)):
                raise AuthorityError("live capability has no controller issuer proof")
            pinned_key = bytes(session.get("controller_capability_public_key") or b"")
            if bytes.fromhex(public_key_hex) != pinned_key:
                raise AuthorityError("live capability issuer is not the bound controller")
            unsigned_capability = {
                key: value for key, value in capability.items()
                if key not in {"issuer_public_key", "issuer_signature"}
            }
            try:
                Ed25519PublicKey.from_public_bytes(pinned_key).verify(
                    bytes.fromhex(signature_hex), _canonical(unsigned_capability)
                )
            except (InvalidSignature, ValueError) as error:
                raise AuthorityError("live capability controller signature is invalid") from error
            capability = unsigned_capability
            if int(capability["expires_at"]) <= int(time.time()) or int(capability["expires_at"]) <= int(capability["issued_at"]):
                raise AuthorityError("live capability is expired")
            capability_ref = hashlib.sha256(_canonical(dict(capability))).hexdigest()
            live_capabilities = session.setdefault("live_capabilities", {})
            if not isinstance(live_capabilities, dict):
                raise AuthorityError("live capability registry is invalid")
            prior = live_capabilities.get(capability_ref)
            if isinstance(prior, Mapping):
                if prior.get("capability") != dict(capability):
                    raise AuthorityError("live capability identity collision")
                if prior.get("consumed"):
                    raise AuthorityError("live capability has already been consumed")
                return {"capability_ref": capability_ref}
            live_capabilities[capability_ref] = {"capability": dict(capability), "consumed": False}
            return {"capability_ref": capability_ref}
        if method == "issue_pre_provider_authorization":
            capability = request.get("capability")
            if not isinstance(capability, Mapping):
                raise AuthorityError("pre-provider capability projection is invalid")
            required = {
                "schema", "purpose", "scope", "session_instance_id",
                "conversation_session_id", "turn_index", "run_id", "run_attempt",
                "generation", "provider_profile", "provider_model", "allowed_phases", "issued_at",
                "expires_at", "nonce", "issuer_public_key", "issuer_signature",
            }
            if set(capability) != required or capability.get("schema") != CODE_MODE_PRE_PROVIDER_AUTHORIZATION_SCHEMA:
                raise AuthorityError("pre-provider capability projection is not exact")
            if capability.get("purpose") != "pre-provider-root-planning" or capability.get("scope") != "current-session-run":
                raise AuthorityError("pre-provider capability scope is invalid")
            if capability.get("session_instance_id") != session["binding"].get("session_instance_id"):
                raise AuthorityError("pre-provider capability session instance is not bound")
            if tuple(capability.get("allowed_phases") or ()) != tuple(CODE_MODE_PRE_PROVIDER_PHASES):
                raise AuthorityError("pre-provider phase allowlist is caller-modified")
            if type(capability.get("turn_index")) is not int or capability["turn_index"] < 0:
                raise AuthorityError("pre-provider turn binding is invalid")
            if type(capability.get("run_attempt")) is not int or capability["run_attempt"] != 1:
                raise AuthorityError("pre-provider attempt binding is invalid")
            if any(not isinstance(capability.get(key), str) or not capability[key].strip() for key in (
                "conversation_session_id", "run_id", "generation", "provider_profile", "provider_model", "nonce",
            )):
                raise AuthorityError("pre-provider capability binding is incomplete")
            if type(capability.get("issued_at")) is not int or type(capability.get("expires_at")) is not int:
                raise AuthorityError("pre-provider capability lifetime is invalid")
            now = int(time.time())
            if capability["issued_at"] > now or capability["expires_at"] <= now or capability["expires_at"] <= capability["issued_at"]:
                raise AuthorityError("pre-provider capability is expired")
            public_hex = capability.get("issuer_public_key")
            signature_hex = capability.get("issuer_signature")
            pinned_key = bytes(session.get("controller_capability_public_key") or b"")
            if (
                not isinstance(public_hex, str) or not re.fullmatch(r"[0-9a-f]{64}", public_hex)
                or not isinstance(signature_hex, str) or not re.fullmatch(r"[0-9a-f]{128}", signature_hex)
                or bytes.fromhex(public_hex) != pinned_key
            ):
                raise AuthorityError("pre-provider capability issuer is not pinned")
            unsigned_capability = {key: value for key, value in capability.items() if key not in {"issuer_public_key", "issuer_signature"}}
            try:
                Ed25519PublicKey.from_public_bytes(pinned_key).verify(
                    bytes.fromhex(signature_hex),
                    b"SITINA-CODE-MODE-PRE-PROVIDER-HANDLE-V1\0" + _canonical(unsigned_capability),
                )
            except (InvalidSignature, ValueError) as error:
                raise AuthorityError("pre-provider controller signature is invalid") from error
            profile = self._profiles.get(str(capability["provider_profile"]))
            if not isinstance(profile, Mapping) or str(profile.get("model") or "") != capability["provider_model"]:
                raise AuthorityError("pre-provider provider profile is not host-authorized")
            scope = {
                key: capability[key]
                for key in (
                    "session_instance_id", "conversation_session_id", "turn_index", "run_id",
                    "run_attempt", "generation", "provider_profile", "provider_model",
                )
            }
            prior_scope = session.get("pre_provider_scope")
            if prior_scope is not None and dict(prior_scope) != scope:
                raise AuthorityError("pre-provider scope changed")
            capability_ref = hashlib.sha256(_canonical(dict(unsigned_capability))).hexdigest()
            prior_handle = self._pre_provider_handle_mappings.get(capability_ref)
            if isinstance(prior_handle, Mapping):
                if prior_handle.get("session") != session_token:
                    raise AuthorityError("pre-provider handle belongs to another host session")
                prior_authorization = prior_handle.get("authorization")
                if not isinstance(prior_authorization, Mapping):
                    raise AuthorityError("pre-provider handle replay mapping is invalid")
                return dict(prior_authorization)
            if prior_scope is not None:
                raise AuthorityError("pre-provider scope already has an issued handle")
            session["pre_provider_scope"] = scope
            nonce_hash = hashlib.sha256(str(capability["nonce"]).encode()).hexdigest()
            body = {
                "schema": CODE_MODE_PRE_PROVIDER_AUTHORIZATION_SCHEMA,
                "purpose": "pre-provider-root-planning",
                "authorization_id": "pre-provider:" + hashlib.sha256(_canonical({**scope, "nonce_hash": nonce_hash})).hexdigest(),
                **scope,
                "allowed_phases": list(CODE_MODE_PRE_PROVIDER_PHASES),
                "issued_at": capability["issued_at"],
                "expires_at": capability["expires_at"],
                "nonce_hash": nonce_hash,
                "issuer_key_id": self._authority_key_id,
            }
            signature = self._authority_private_key.sign(_canonical(body))
            authorization = {**body, "authority_signature_hex": signature.hex()}
            self._pre_provider_authorizations[authorization["authorization_id"]] = {
                "session": session_token,
                "authorization": authorization,
                "capability_ref": capability_ref,
                "used_call_identities": set(),
            }
            self._pre_provider_handle_mappings[capability_ref] = {
                "session": session_token,
                "authorization": dict(authorization),
            }
            return authorization
        if method == "acceptance_transaction":
            body = request.get("locators")
            if not isinstance(body, Mapping):
                raise AuthorityError("acceptance requires durable locators")
            body = dict(body)
            binding = session["binding"]
            if body.get("runtime_authority_handle_hash") != binding.get("runtime_authority_handle_hash"):
                raise AuthorityError("acceptance locator projection is not bound to this runtime")
            if body.get("schema") != "CODE_MODE_ACCEPTANCE_LOCATOR_REQUEST_V2":
                raise AuthorityError("acceptance locator schema is invalid")
            required = {
                "schema", "run_locator", "request_locator", "candidate_locator",
                "package_locator", "core_locator", "review_locator", "gate_locator",
                "completion_plan_locator",
                "runtime_authority_handle_hash",
            }
            if set(body) != required:
                raise AuthorityError("acceptance request accepts locators only")
            snapshot = self._journal_snapshot()
            run_id, stream_id, generation, stream_version = self._bound_run(body.get("run_locator"), snapshot=snapshot)
            cas_locators = {
                name: body.get(name)
                for name in ("request_locator", "candidate_locator", "package_locator", "core_locator", "review_locator", "gate_locator", "completion_plan_locator")
            }
            resolved = {name: self._cas_locator(value, role=name) for name, value in cas_locators.items()}
            self._validate_reopened_facts(
                run_id=run_id, generation=generation,
                locators=cas_locators, resolved=resolved, snapshot=snapshot,
            )
            self._await_test_acceptance_snapshot_barrier()
            request_body = resolved["request_locator"]["payload"]
            self._lock_session_scope(
                session, run_id=run_id, generation=generation,
                session_id=str(request_body.get("session_id") or ""),
                stream_id="session/" + str(request_body.get("session_id") or ""),
                session_instance_id=str(request_body.get("session_instance_id") or ""),
                run_attempt=request_body.get("run_attempt"),
                authorization_ref=str(request_body.get("authorization_ref") or ""),
            )
            _locator_manifest_hash, proof_manifest_hash = self._locator_commitment(cas_locators)
            event_projection_hash = self._acceptance_event_commitment(
                run_id=run_id, generation=generation, locators=cas_locators, resolved=resolved,
            )
            operation_id = "code-mode-accept-" + hashlib.sha256(_canonical({"run": body["run_locator"], "locators": cas_locators})).hexdigest()[:32]
            # The caller supplies only locators and a command identity.  The
            # signed envelope is constructed here from the fixed acceptance
            # operation, never by signing a caller-provided operation body.
            envelope = {
                "schema": "AUTHORITY_ACCEPTANCE_TRANSACTION_V1",
                "operation": "LOGICAL_ACCEPTANCE_OPERATION_V1",
                "operation_id": operation_id,
                "run_id": run_id,
                "stream_id": stream_id,
                "generation": generation,
                "expected_stream_version": stream_version,
                "parent_operation_hash": hashlib.sha256(_canonical(body["request_locator"])).hexdigest(),
                "issuer_key_id": self._authority_key_id,
                "completion_plan_hash": resolved["completion_plan_locator"]["object_hash"],
                "event_projection_hash": event_projection_hash,
                "proof_manifest_hash": proof_manifest_hash,
            }
            envelope["payload_hash"] = hashlib.sha256(_canonical({**envelope, "payload_hash": ""})).hexdigest()
            # Acceptance is a write authorization, so the facts used to
            # construct the envelope must still be the same authenticated
            # snapshot immediately before signing.  Reopening only the
            # locators is insufficient: an advance, cancel, conversation
            # event, or frontier change must invalidate the operation.
            before_sign_snapshot = self._journal_snapshot()
            if self._snapshot_hash(before_sign_snapshot) != self._snapshot_hash(snapshot):
                raise AuthorityError("authenticated Journal snapshot changed before acceptance signing")
            before_sign_resolved = {
                name: self._cas_locator(value, role=name)
                for name, value in cas_locators.items()
            }
            self._validate_reopened_facts(
                run_id=run_id, generation=generation,
                locators=cas_locators, resolved=before_sign_resolved,
                snapshot=before_sign_snapshot,
            )
            if before_sign_resolved["request_locator"]["payload"].get("authorization_ref") != request_body.get("authorization_ref"):
                raise AuthorityError("acceptance authorization binding changed before signing")
            signature = self._authority_private_key.sign(_canonical(envelope))
            return {**envelope, "signature_hex": signature.hex()}
        if method == "request_completion_plan":
            inputs = request.get("locators")
            if not isinstance(inputs, Mapping):
                raise AuthorityError("completion plan requires durable locators")
            allowed = {
                "schema", "run_locator", "conversation_locator", "request_locator",
                "candidate_locator", "package_locator", "core_locator", "review_locator",
                "gate_locator", "terminal_stage_draft_locator", "root_stage_draft_locator",
                "conversation_stage_draft_locator", "runtime_authority_handle_hash",
            }
            if set(inputs) != allowed or inputs.get("schema") != "CODE_MODE_COMPLETION_LOCATOR_REQUEST_V2":
                raise AuthorityError("completion plan accepts locators only")
            body = dict(inputs)
            if body.get("runtime_authority_handle_hash") != session["binding"].get("runtime_authority_handle_hash"):
                raise AuthorityError("completion plan runtime binding mismatch")
            snapshot = self._journal_snapshot()
            run_id, stream_id, generation, start = self._bound_run(body.get("run_locator"), snapshot=snapshot)
            conversation_stream_id, conversation_start = self._bound_conversation(body.get("conversation_locator"), snapshot=snapshot)
            cas_locators = {
                name: body.get(name)
                for name in ("request_locator", "candidate_locator", "package_locator", "core_locator", "review_locator", "gate_locator")
            }
            stage_draft_locators = {
                "terminal": body.get("terminal_stage_draft_locator"),
                "root": body.get("root_stage_draft_locator"),
                "conversation": body.get("conversation_stage_draft_locator"),
            }
            if any(not isinstance(value, str) for value in stage_draft_locators.values()):
                raise AuthorityError("completion plan requires all stage draft locators")
            stage_drafts = {
                stage: self._cas_locator(value, role=f"{stage}_stage_draft_locator")
                for stage, value in stage_draft_locators.items()
            }
            for stage, draft in stage_drafts.items():
                draft_payload = draft.get("payload")
                if (
                    not isinstance(draft_payload, Mapping)
                    or draft_payload.get("schema") != "CODE_MODE_STAGE_DRAFT_V1"
                    or draft_payload.get("stage") != stage
                    or draft_payload.get("run_id") != run_id
                    or draft_payload.get("generation") != generation
                    or not isinstance(draft_payload.get("event_projection"), list)
                    or not isinstance(draft_payload.get("proof_manifest"), list)
                ):
                    raise AuthorityError(f"{stage} stage draft is not bound to the reopened snapshot")
            resolved = {name: self._cas_locator(value, role=name) for name, value in cas_locators.items()}
            self._validate_reopened_facts(
                run_id=run_id, generation=generation,
                locators=cas_locators, resolved=resolved, snapshot=snapshot,
            )
            # Stage drafts are untrusted locator inputs.  Validate each one
            # against the same reopened snapshot before constructing any
            # stage transaction or completion-plan signature.  A caller may
            # not submit a self-consistent but semantically wrong draft.
            for stage, draft in stage_drafts.items():
                self._validate_stage_draft(
                    draft,
                    stage=stage,
                    run_id=run_id,
                    generation=generation,
                    resolved=resolved,
                    session_token=str(session_token),
                )
            request_body = resolved["request_locator"]["payload"]
            self._lock_session_scope(
                session, run_id=run_id, generation=generation,
                session_id=str(request_body.get("session_id") or ""),
                stream_id=conversation_stream_id,
                session_instance_id=str(request_body.get("session_instance_id") or ""),
                run_attempt=request_body.get("run_attempt"),
                authorization_ref=str(request_body.get("authorization_ref") or ""),
            )
            snapshot_hash = self._snapshot_hash(snapshot)
            base = {
                "schema": body["schema"], "run_locator": body["run_locator"],
                "conversation_locator": body["conversation_locator"], **cas_locators,
                "snapshot_hash": snapshot_hash,
            }
            operations = []
            parent = hashlib.sha256(_canonical({"domain": "CODE_MODE_COMPLETION_PLAN_BASE", "base": base})).hexdigest()
            for operation, expected_start, expected_end in (
                # The plan fact is start+1 and the two-event acceptance pair
                # is start+2..start+3.  The following values are assigned
                # event versions (the Journal expected version is the
                # predecessor), never global Journal positions.
                ("LOGICAL_TERMINAL_OPERATION_V1", start + 4, start + 8),
                ("LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1", start + 9, start + 9),
                ("LOGICAL_CONVERSATION_COMPLETION_V1", conversation_start + 1, conversation_start + 1),
            ):
                is_conversation = operation == "LOGICAL_CONVERSATION_COMPLETION_V1"
                event_count = 5 if operation == "LOGICAL_TERMINAL_OPERATION_V1" else 1
                terminal_stage = stage_drafts.get("terminal") if isinstance(stage_drafts, Mapping) else None
                terminal_stage_payload = terminal_stage.get("payload") if isinstance(terminal_stage, Mapping) else None
                terminal_projection = terminal_stage_payload.get("event_projection") if isinstance(terminal_stage_payload, Mapping) else None
                terminal_state = (
                    terminal_projection[-1].get("payload", {}).get("terminal_state")
                    if isinstance(terminal_projection, list) and terminal_projection
                    and isinstance(terminal_projection[-1], Mapping)
                    and isinstance(terminal_projection[-1].get("payload"), Mapping)
                    else None
                )
                terminal_event_type = (
                    "code-mode.terminal-success" if terminal_state == "SUCCEEDED"
                    else "code-mode.terminal-failed" if terminal_state == "FAILED"
                    else None
                )
                if terminal_event_type is None:
                    raise AuthorityError("terminal operation state is invalid")
                event_schema_order = (
                    ["run.closing", "protocol.terminal.negative.probe.rejected", "protocol.terminal.full.validation.accepted", "protocol.run.evidence.package.sealed", terminal_event_type]
                    if event_count == 5 else (["code-mode.conversation-completion"] if is_conversation else ["code-mode.final-root"])
                )
                locator_values = [resolved[name] for name in ("request_locator", "candidate_locator", "package_locator", "core_locator", "review_locator", "gate_locator")]
                logical_binding = {
                    "run_id": run_id,
                    "stream_id": conversation_stream_id if is_conversation else stream_id,
                    "generation": generation,
                    "session_id": resolved["request_locator"]["payload"].get("session_id"),
                    "session_instance_id": resolved["request_locator"]["payload"].get("session_instance_id"),
                    "run_attempt": resolved["request_locator"]["payload"].get("run_attempt"),
                    "turn_index": resolved["request_locator"]["payload"].get("turn_index"),
                    "candidate_id": resolved["candidate_locator"]["payload"].get("candidate_id"),
                    "tree_hash": resolved["candidate_locator"]["payload"].get("tree_hash"),
                    "snapshot_hash": snapshot_hash,
                    "snapshot_frontier": [
                        {
                            "stream_id": str(frame.transaction.stream_id),
                            "last_stream_version": int(frame.transaction.last_stream_version),
                            "transaction_hash": str(getattr(frame, "transaction_hash", "")),
                        }
                        for frame in snapshot
                    ],
                }
                logical_event_projection = [
                    {
                        "event_type": str(event_type),
                        "logical_binding_hash": hashlib.sha256(_canonical(logical_binding)).hexdigest(),
                    }
                    for event_type in event_schema_order
                ]
                logical = {
                    "operation": operation,
                    "stream_id": conversation_stream_id if is_conversation else stream_id,
                    "run_id": run_id,
                    "generation": generation,
                    "expected_start_version": expected_start,
                    "expected_end_version": expected_end,
                    "parent_logical_hash": parent,
                    "bindings": base,
                    "event_count": event_count,
                    "event_schema_order": event_schema_order,
                    "logical_binding": logical_binding,
                    "logical_event_projection": logical_event_projection,
                    "event_projection_hash": hashlib.sha256(_canonical(logical_event_projection)).hexdigest(),
                    # Future physical objects and their receipts are excluded
                    # from the pre-signed plan.  The stage append binds them
                    # through its actual proof manifest instead.
                    "proof_manifest_hash": hashlib.sha256(_canonical([
                        {"role": name, "purpose_class": str(resolved[name]["proof_manifest"].get("purpose_class") or "")}
                        for name in sorted(resolved)
                    ])).hexdigest(),
                    "proof_purpose_order": [
                        str(resolved[name]["proof_manifest"].get("purpose_class") or "")
                        for name in sorted(resolved)
                    ],
                    "cas_object_hashes": [],
                    "frontier_commitment": hashlib.sha256(_canonical({
                        "stream_id": stream_id, "stream_version": start,
                        "snapshot_hash": logical_binding["snapshot_hash"],
                    })).hexdigest(),
                }
                stage_name = {
                    "LOGICAL_TERMINAL_OPERATION_V1": "terminal",
                    "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1": "root",
                    "LOGICAL_CONVERSATION_COMPLETION_V1": "conversation",
                }[operation]
                stage_payload = stage_drafts[stage_name]["payload"]
                logical.update({
                    "stage_draft_ref": stage_drafts[stage_name]["reference_id"],
                    "stage_draft_hash": stage_drafts[stage_name].get("content_hash"),
                    "stage_actual_event_projection": list(stage_payload["event_projection"]),
                    "stage_actual_event_projection_hash": stage_payload.get("event_projection_hash"),
                    "stage_actual_proof_manifest": list(stage_payload["proof_manifest"]),
                    "stage_actual_proof_manifest_hash": stage_payload.get("proof_manifest_hash"),
                })
                logical_hash = planned_operation_hash(logical)
                logical_operation_id = "code-mode-op-" + logical_hash[:32]
                stage_transaction_unsigned = {
                    "schema": "AUTHORITY_STAGE_TRANSACTION_V1",
                    "stage": stage_name,
                    "operation": operation,
                    "logical_operation_id": logical_operation_id,
                    "logical_operation_hash": logical_hash,
                    "run_id": run_id,
                    "stream_id": conversation_stream_id if is_conversation else stream_id,
                    "generation": generation,
                    "snapshot_hash": snapshot_hash,
                    "plan_base_hash": hashlib.sha256(_canonical(base)).hexdigest(),
                    "parent_logical_hash": logical["parent_logical_hash"],
                    "expected_start_version": expected_start,
                    "expected_end_version": expected_end,
                    "stage_draft_ref": logical["stage_draft_ref"],
                    "stage_draft_hash": logical["stage_draft_hash"],
                    "stage_actual_event_projection": list(logical["stage_actual_event_projection"]),
                    "stage_actual_event_projection_hash": logical["stage_actual_event_projection_hash"],
                    "stage_actual_proof_manifest": list(logical["stage_actual_proof_manifest"]),
                    "stage_actual_proof_manifest_hash": logical["stage_actual_proof_manifest_hash"],
                    "issuer_key_id": self._authority_key_id,
                }
                stage_signature = self._authority_private_key.sign(_canonical(stage_transaction_unsigned))
                stage_transaction = {
                    **stage_transaction_unsigned,
                    "signature_hex": stage_signature.hex(),
                }
                stage_transaction_hash = hashlib.sha256(_canonical(stage_transaction)).hexdigest()
                operations.append({
                    **logical,
                    "logical_operation_id": logical_operation_id,
                    "logical_operation_hash": logical_hash,
                    "stage_transaction": stage_transaction,
                    "stage_transaction_hash": stage_transaction_hash,
                })
                parent = logical_hash
            body["operations"] = operations
            body["schema"] = "CODE_MODE_COMPLETION_PLAN_V1"
            body["run_id"], body["stream_id"], body["generation"] = run_id, stream_id, generation
            body["snapshot_hash"] = snapshot_hash
            body["snapshot_frontier"] = list(operations[0]["logical_binding"]["snapshot_frontier"])
            body["accepted_at"] = 0
            body["conversation_stream_id"] = conversation_stream_id
            body["conversation_stream_start_version"] = conversation_start
            body["issuer_key_id"] = self._authority_key_id
            if self._snapshot_hash(self._journal_snapshot()) != snapshot_hash:
                raise AuthorityError("authenticated Journal snapshot changed before plan signing")
            signature = self._authority_private_key.sign(_canonical(body))
            return {**body, "authority_signature_hex": signature.hex()}
        if method == "issue_canary":
            locators = request.get("locators")
            if not isinstance(locators, Mapping) or locators.get("schema") != "CODE_MODE_CANARY_LOCATOR_REQUEST_V2":
                raise AuthorityError("canary issuance requires typed durable locators")
            expected_keys = {
                "schema", "run_locator", "candidate_locator", "package_locator",
                "core_locator", "request_locator", "review_locator", "gate_locator",
                "live_capability_ref",
            }
            if set(locators) != expected_keys:
                raise AuthorityError("canary locator request contains caller-built facts")
            for key in sorted(expected_keys - {"schema", "provider_profile", "provider_model"}):
                value = locators.get(key)
                if not isinstance(value, str) or not value:
                    raise AuthorityError("canary locator request is incomplete")
            capability_ref = locators.get("live_capability_ref")
            live_capabilities = session.get("live_capabilities")
            capability_record = live_capabilities.get(capability_ref) if isinstance(live_capabilities, Mapping) else None
            if (
                not isinstance(capability_ref, str) or not re.fullmatch(r"[0-9a-f]{64}", capability_ref)
                or not isinstance(capability_record, Mapping) or capability_record.get("consumed")
                or not isinstance(capability_record.get("capability"), Mapping)
            ):
                raise AuthorityError("canary requires a current one-use live capability")
            capability = capability_record["capability"]
            if capability.get("purpose") not in CODE_MODE_LIVE_CAPABILITY_PURPOSES or int(capability.get("expires_at") or 0) <= int(time.time()):
                raise AuthorityError("live capability is expired or has an invalid purpose")
            snapshot = self._journal_snapshot()
            run_id, stream_id, generation, _run_version = self._bound_run(locators["run_locator"], snapshot=snapshot)
            resolved = {
                role: self._cas_locator(locators[role], role=role)
                for role in (
                    "candidate_locator", "package_locator", "core_locator",
                    "request_locator", "review_locator", "gate_locator",
                )
            }
            request_body = resolved["request_locator"]["payload"]
            session_id = request_body.get("session_id") if isinstance(request_body, Mapping) else None
            session_instance_id = request_body.get("session_instance_id") if isinstance(request_body, Mapping) else None
            run_attempt = request_body.get("run_attempt") if isinstance(request_body, Mapping) else None
            turn_index = request_body.get("turn_index") if isinstance(request_body, Mapping) else None
            if not isinstance(session_id, str) or not session_id or not isinstance(session_instance_id, str) or not session_instance_id:
                raise AuthorityError("canary request lacks authenticated session binding")
            if type(run_attempt) is not int or run_attempt < 1 or type(turn_index) is not int or turn_index < 0:
                raise AuthorityError("canary request lacks authenticated attempt binding")
            self._lock_session_scope(
                session, run_id=run_id, generation=generation,
                session_id=session_id, stream_id=stream_id,
                session_instance_id=session_instance_id,
                run_attempt=run_attempt,
                authorization_ref=str(request_body.get("authorization_ref") or ""),
            )
            self._validate_reopened_facts(
                run_id=run_id, generation=generation,
                locators={key: str(locators[key]) for key in locators if key.endswith("_locator") and key != "run_locator"},
                resolved=resolved, snapshot=snapshot,
            )
            if self._snapshot_hash(self._journal_snapshot()) != self._snapshot_hash(snapshot):
                raise AuthorityError("authenticated Journal snapshot changed before canary signing")
            if capability.get("run_id") != run_id:
                raise AuthorityError("live capability run binding changed")
            if capability.get("session_id") != session_id:
                raise AuthorityError("live capability conversation binding changed")
            gate = resolved["gate_locator"]["payload"]
            if gate.get("status") != "CODE_MODE_READY":
                raise AuthorityError("canary requires an authenticated CODE_MODE_READY gate")
            candidate = resolved["candidate_locator"]["payload"]
            package = resolved["package_locator"]["payload"]
            gate = resolved["gate_locator"]["payload"]
            provider_tuples: list[tuple[str, str]] = []
            for role, body in (
                ("request", request_body), ("package", package), ("gate", gate),
            ):
                if not isinstance(body, Mapping):
                    raise AuthorityError("canary " + role + " provider binding is invalid")
                profile_name_value = body.get("provider_profile")
                provider_model_value = body.get("provider_model")
                if (
                    type(profile_name_value) is not str or not profile_name_value
                    or type(provider_model_value) is not str or not provider_model_value
                ):
                    raise AuthorityError("canary " + role + " provider binding is incomplete")
                provider_tuples.append((profile_name_value, provider_model_value))
            if len(set(provider_tuples)) != 1:
                raise AuthorityError("canary provider profile/model bindings disagree")
            profile_name, provider_model = provider_tuples[0]
            provider = self._profiles.get(profile_name)
            if (
                not isinstance(provider, Mapping)
                or type(provider.get("model")) is not str
                or not provider.get("model")
                or provider.get("model") != provider_model
            ):
                raise AuthorityError("canary provider profile is not host-authorized")
            # The current execution authorization is another authenticated
            # source of provider scope.  It is not a caller-provided scalar.
            latest_attempt, latest_authorization_ref, latest_authorization = self._latest_attempt_binding(
                snapshot, run_id,
            )
            self._validate_canary_attempt_provider_binding(
                latest_attempt=latest_attempt,
                latest_authorization_ref=latest_authorization_ref,
                latest_authorization=latest_authorization,
                expected_scope={
                    "session_instance_id": session_instance_id,
                    "conversation_session_id": session_id,
                    "turn_index": turn_index,
                    "run_id": run_id,
                    "run_attempt": run_attempt,
                    "generation": generation,
                    "provider_profile": profile_name,
                    "provider_model": provider_model,
                },
                pre_provider_scope=session.get("pre_provider_scope"),
            )
            auth_ref = request_body.get("authorization_ref")
            if not isinstance(auth_ref, str) or not auth_ref:
                raise AuthorityError("canary request lacks current execution authorization")
            if auth_ref != latest_authorization_ref:
                raise AuthorityError("canary request authorization is not current")
            now = int(time.time())
            body = {
                "schema": "CODE_MODE_CANARY_AUTHORIZATION_V2",
                "candidate_id": candidate.get("candidate_id"),
                "tree_hash": candidate.get("tree_hash"),
                "source_manifest_hash": candidate.get("source_manifest_hash"),
                "worktree_digest": candidate.get("worktree_digest"),
                "session_id": session_id,
                "run_id": run_id,
                "workspace": str(self._workspace),
                "session_instance_id": session_instance_id,
                "run_attempt": run_attempt,
                "generation": generation,
                "authorization_ref": auth_ref,
                "provider_profile": profile_name,
                "provider_model": provider_model,
                "fallback_allowed": False,
                "issued_at": now,
                "expires_at": min(
                    now + 900,
                    *[
                        int(resolved[role]["payload"].get("expires_at"))
                        for role in ("package_locator", "request_locator", "review_locator")
                        if type(resolved[role]["payload"].get("expires_at")) is int
                    ],
                ),
                "nonce": secrets.token_urlsafe(24),
                "candidate_locator": locators["candidate_locator"],
                "package_locator": locators["package_locator"],
                "core_locator": locators["core_locator"],
                "request_locator": locators["request_locator"],
                "review_locator": locators["review_locator"],
                "gate_locator": locators["gate_locator"],
                "legacy_bplus_authorization": False,
            }
            if body["expires_at"] <= now:
                raise AuthorityError("canary upstream evidence is expired")
            binding = session["binding"]
            body.update({"broker_session": session_token, "broker_binding_hash": _hash(binding)})
            body["authorization_id"] = _hash(body)
            authorization = self._signed(body)
            capability_record["consumed"] = True  # type: ignore[index]
            self._canaries[authorization["authorization_id"]] = {"session": session_token, "authorization": authorization, "consumed": False}
            return authorization
        if method == "transport_bind_pre_provider":
            auth = request.get("authorization")
            record = self._pre_provider_authorizations.get(
                str(auth.get("authorization_id")) if isinstance(auth, Mapping) else ""
            )
            expected = record.get("authorization") if isinstance(record, Mapping) else None
            if (
                not isinstance(record, Mapping) or record.get("session") != session_token
                or not isinstance(expected, Mapping) or not isinstance(auth, Mapping)
                or dict(auth) != dict(expected)
                or int(expected.get("expires_at") or 0) <= int(time.time())
            ):
                raise AuthorityError("pre-provider authorization is invalid")
            if "attempt_execution" in session.get("authorization_domains", {}):
                raise AuthorityError("pre-provider root authorization is no longer active after Forge bind")
            session["transport_authorization_id"] = str(expected["authorization_id"])
            session["transport_authorization_kind"] = "pre-provider"
            session["transport_authorization_domain"] = "pre_provider_root"
            session.setdefault("authorization_domains", {})["pre_provider_root"] = {
                "authorization_id": str(expected["authorization_id"]),
                "authorization": dict(expected),
            }
            return {"bound": True}
        if method == "transport_bind_forge":
            if request.get("capability") != session.get("transport_capability"):
                raise AuthorityError("transport capability is invalid")
            if set(request) != {"method", "session", "capability", "child_authorization_locator"}:
                raise AuthorityError("Forge transport binding accepts only the child locator")
            child_locator = request.get("child_authorization_locator")
            if not isinstance(child_locator, str) or not child_locator.startswith("cas:"):
                raise AuthorityError("Forge child authorization locator is invalid")
            snapshot = self._journal_snapshot()
            matching: list[Mapping[str, Any]] = []
            for frame in snapshot:
                for event in frame.transaction.events:
                    payload = event.payload
                    if (
                        frame.transaction.stream_id.startswith("run/")
                        and isinstance(payload, Mapping)
                        and payload.get("schema") == CODE_MODE_FORGE_CHILD_AUTHORIZATION_SCHEMA
                        and payload.get("event_type") == CODE_MODE_FORGE_CHILD_AUTHORIZATION_EVENT_TYPE
                        and payload.get("authorization_receipt_ref") == child_locator
                        and tuple(event.object_refs) == (child_locator,)
                    ):
                        matching.append(payload)
            if len(matching) != 1:
                raise AuthorityError("Forge child authorization mapping is not unique")
            child = dict(matching[0])
            required = {
                "schema", "event_type", "purpose", "domain", "session_instance_id",
                "conversation_session_id", "turn_index", "run_id", "child_run_id",
                "run_attempt", "generation", "authorization_ref",
                "parent_authorization_ref", "parent_authorization_hash", "workspace",
                "scope", "execution_root", "risk_level", "provider_profile", "provider_model", "expires_at",
                "authorization_receipt_ref", "authorization_receipt_hash", "payload_hash",
            }
            plumbing = {"runtime_namespace", "actor_id", "causation_command_id", "policy_hash", "fact_hash"}
            if set(child) - plumbing != required:
                raise AuthorityError("Forge child authorization mapping is not exact")
            if child.get("purpose") != CODE_MODE_FORGE_CHILD_AUTHORIZATION_PURPOSE or child.get("domain") != "attempt_execution":
                raise AuthorityError("Forge child authorization domain is invalid")
            if child.get("session_instance_id") != session["binding"].get("session_instance_id"):
                raise AuthorityError("Forge child authorization session is not current")
            if type(child.get("run_attempt")) is not int or child.get("run_attempt") < 1:
                raise AuthorityError("Forge child authorization attempt is invalid")
            root_run_id = str(child.get("run_id") or "")
            if not root_run_id or child.get("child_run_id") != f"forge-exec-{root_run_id}-{child['run_attempt']}":
                raise AuthorityError("Forge child authorization run is invalid")
            current_attempt, current_ref, current_auth = self._latest_attempt_binding(snapshot, root_run_id)
            current_execution_auth = self._current_execution_authorization(
                current_attempt, current_auth,
            )
            if current_attempt != child["run_attempt"] or current_ref != child.get("parent_authorization_ref"):
                raise AuthorityError("Forge child authorization is not the current attempt")
            if child.get("generation") != current_execution_auth.get("generation"):
                raise AuthorityError("Forge child authorization generation changed")
            try:
                expected_child = forge_child_authorization_projection(
                    session_instance_id=child["session_instance_id"],
                    conversation_session_id=child["conversation_session_id"],
                    turn_index=child["turn_index"], run_id=child["run_id"],
                    child_run_id=child["child_run_id"], run_attempt=child["run_attempt"],
                    generation=child["generation"],
                    parent_authorization_ref=child["parent_authorization_ref"],
                    parent_authorization_hash=child["parent_authorization_hash"],
                    authorization_ref=child["authorization_ref"],
                    workspace=child["workspace"], scope=child["scope"],
                    execution_root=child["execution_root"], risk_level=child["risk_level"],
                    provider_profile=child["provider_profile"],
                    provider_model=child["provider_model"], expires_at=child["expires_at"],
                    payload_hash=child["payload_hash"],
                )
            except Exception as error:
                raise AuthorityError("Forge child authorization logical projection is invalid") from error
            if canonical_json_bytes(expected_child) != canonical_json_bytes(
                {key: child[key] for key in expected_child}
            ):
                raise AuthorityError("Forge child authorization logical projection changed")
            # Forge is only reachable after the authenticated root planning FSM
            # has committed exactly one selection.  The host derives this from
            # the same verified frame set used for the child mapping; a caller
            # cannot advance the FSM by supplying a phase, role, or selected
            # agent in the bind RPC.
            root_state = self._root_fsm_from_snapshot(snapshot, root_run_id)
            if root_state == "CLOSED_REJECTED":
                raise AuthorityError(
                    "Forge root planning FSM closed after rejected revision",
                    reason_code="ROOT_REWORK_CLOSED_REJECTED",
                )
            selections = self._root_fact_events(
                snapshot, root_run_id, "CODE_MODE_ROOT_SELECTION_FACT_V1",
                "code-mode.root-selection-committed",
            )
            if len(selections) != 1:
                raise AuthorityError("Forge requires one authenticated root selection")
            selection = selections[0]
            required_selection = {
                "schema", "event_type", "purpose", "purpose_class", "run_id",
                "session_instance_id", "conversation_session_id", "turn_index",
                "generation", "run_attempt", "selected_agent_id", "selected_agent_role",
                "selected_agent_capabilities", "selected_task_id", "selected_output_hash",
                "selected_output_ref", "selected_provider_call_id",
                "selected_dispatch_commitment",
            }
            selection_plumbing = {
                "runtime_namespace", "actor_id", "causation_command_id",
                "policy_hash", "fact_hash",
            }
            if set(selection) - selection_plumbing != required_selection or any(
                not isinstance(selection.get(field), str) or not selection.get(field)
                for field in (
                    "schema", "event_type", "purpose", "purpose_class", "run_id",
                    "session_instance_id", "conversation_session_id", "generation",
                    "selected_agent_id", "selected_agent_role", "selected_task_id",
                    "selected_output_hash", "selected_output_ref", "selected_provider_call_id",
                    "selected_dispatch_commitment",
                )
            ) or type(selection.get("turn_index")) is not int or selection.get("turn_index") < 0 or type(selection.get("run_attempt")) is not int or selection.get("run_attempt") < 1 or not isinstance(selection.get("selected_agent_capabilities"), list):
                raise AuthorityError("authenticated root selection is incomplete")
            if root_state != "ROOT_COMPLETE":
                raise AuthorityError(
                    "Forge root planning FSM has not completed authenticated selection",
                    reason_code="ROOT_PLANNING_SELECTION_INCOMPLETE",
                )
            if selection.get("session_instance_id") != session["binding"].get("session_instance_id"):
                raise AuthorityError("root selection session instance changed")
            if selection.get("conversation_session_id") != current_execution_auth.get("session_id"):
                raise AuthorityError("root selection conversation changed")
            if (
                selection.get("turn_index") != current_execution_auth.get("turn_index")
                or selection.get("generation") != current_execution_auth.get("generation")
            ):
                raise AuthorityError("root selection turn changed")
            # Selection is a root-planning fact.  It remains anchored to the
            # initial pre-Forge scope even when the run has since advanced
            # through a rework attempt.  The Forge child below is still
            # checked against the authenticated current attempt/ref.
            planning_scope = session.get("pre_provider_scope")
            if not isinstance(planning_scope, Mapping):
                raise AuthorityError("root selection planning scope is missing")
            if (
                planning_scope.get("run_id") != root_run_id
                or type(planning_scope.get("run_attempt")) is not int
                or planning_scope.get("run_attempt") < 1
                or selection.get("run_attempt") != planning_scope.get("run_attempt")
            ):
                raise AuthorityError("root selection is not anchored to the initial planning attempt")
            parent_events = self._root_fact_events(
                snapshot, root_run_id, CODE_MODE_EXECUTION_PARENT_SCHEMA,
                CODE_MODE_EXECUTION_PARENT_EVENT_TYPE,
            )
            current_parent_events = [
                fact for fact in parent_events
                if fact.get("parent_authorization_ref") == current_ref
            ]
            if len(current_parent_events) != 1:
                raise AuthorityError("Forge requires one authenticated current execution parent")
            parent_event = current_parent_events[0]
            parent_ref = parent_event.get("authorization_receipt_ref")
            if (
                parent_event.get("parent_authorization_ref") != current_ref
                or not isinstance(parent_ref, str) or not parent_ref.startswith("cas:")
                or parent_event.get("parent_authorization_hash") != child.get("parent_authorization_hash")
            ):
                raise AuthorityError("Forge parent mapping is not the current authenticated parent")
            try:
                parent_object = self._formal_cas().resolve_reference(parent_ref)
                parent_proof = self._formal_cas().verify_existing(parent_object)
                parent_raw = self._formal_cas().open_verified(parent_object)
                parent_body = parse_canonical_json(parent_raw)
            except Exception as error:
                raise AuthorityError("Forge parent CAS proof cannot be reopened") from error
            if (
                not isinstance(parent_body, Mapping)
                or parent_proof.object_ref.reference_id != parent_ref
                or parent_proof.object_ref.object_id != parent_ref.removeprefix("cas:")
                or parent_proof.purpose_class != CODE_MODE_EXECUTION_PARENT_PURPOSE
                or parent_proof.fresh_verified is not True
                or parent_proof.no_replace_published is not True
                or parent_event.get("authorization_receipt_hash") != parent_proof.object_ref.plaintext_commitment
            ):
                raise AuthorityError("Forge parent CAS ownership or purpose is invalid")
            try:
                parent_projection = execution_parent_projection(
                    authorization_token_hash=parent_body["authorization_token_hash"],
                    authorization_ref=parent_body["authorization_ref"],
                    session_instance_id=parent_body["session_instance_id"],
                    conversation_session_id=parent_body["conversation_session_id"],
                    turn_index=parent_body["turn_index"],
                    generation=parent_body["generation"],
                    provider_profile=parent_body["provider_profile"],
                    provider_model=parent_body["provider_model"],
                    session_id=parent_body["session_id"],
                    run_id=parent_body["run_id"],
                    intent_hash=parent_body["intent_hash"],
                    workspace=parent_body["workspace"],
                    scope=parent_body["scope"],
                    risk_level=parent_body["risk_level"],
                    attempt=parent_body["attempt"],
                    expires_at=parent_body["expires_at"],
                )
            except Exception as error:
                raise AuthorityError("Forge parent CAS projection is invalid") from error
            expected_parent_body = {
                **parent_projection,
                "parent_authorization_hash": execution_parent_hash(parent_projection),
            }
            if (
                canonical_json_bytes(dict(parent_body)) != canonical_json_bytes(expected_parent_body)
                or parent_event.get("parent_authorization_hash") != expected_parent_body["parent_authorization_hash"]
                or parent_body.get("authorization_ref") != current_ref
                or parent_body.get("run_id") != root_run_id
                or parent_body.get("session_instance_id") != session["binding"].get("session_instance_id")
                or parent_body.get("generation") != current_execution_auth.get("generation")
            ):
                raise AuthorityError("Forge parent CAS projection changed")
            if child.get("parent_authorization_hash") != expected_parent_body["parent_authorization_hash"]:
                raise AuthorityError("Forge child parent hash is not independently authenticated")
            selected_calls = self._root_fact_events(
                snapshot, root_run_id, "CODE_MODE_ROOT_SETTLED_FACT_V1", "code-mode.root-call-settled"
            )
            selected_calls = [
                fact for fact in selected_calls
                if fact.get("provider_call_id") == selection.get("selected_provider_call_id")
            ]
            if len(selected_calls) != 1:
                raise AuthorityError("root selection has no unique settled provider call")
            selected_call = selected_calls[0]
            for selection_field, call_field in (
                ("selected_agent_id", "agent_id"), ("selected_task_id", "task_id"),
                ("selected_agent_role", "role"),
                ("selected_dispatch_commitment", "dispatch_commitment"),
            ):
                if selection.get(selection_field) != selected_call.get(call_field):
                    raise AuthorityError("root selection does not bind settled call")
            selected_results = self._root_fact_events(
                snapshot, root_run_id, "CODE_MODE_ROOT_RESULT_ACCEPTED_V1", "code-mode.root-result-accepted"
            )
            selected_results = [
                fact for fact in selected_results
                if fact.get("provider_call_id") == selection.get("selected_provider_call_id")
            ]
            if len(selected_results) != 1:
                raise AuthorityError("root selection has no unique accepted business result")
            selected_result = selected_results[0]
            for selection_field, result_field in (
                ("selected_task_id", "task_id"),
                ("selected_output_hash", "output_hash"),
                ("selected_output_ref", "output_ref"),
            ):
                if selection.get(selection_field) != selected_result.get(result_field):
                    raise AuthorityError("root selection does not bind accepted result")
            session["root_fsm_state"] = "ROOT_COMPLETE"
            if child.get("conversation_session_id") != current_execution_auth.get("session_id"):
                raise AuthorityError("Forge child authorization conversation changed")
            if child.get("provider_profile") not in self._profiles:
                raise AuthorityError("Forge child provider profile is not host-authorized")
            if str(self._profiles[child["provider_profile"]].get("model") or "") != child.get("provider_model"):
                raise AuthorityError("Forge child provider model is not host-authorized")
            try:
                child_object = self._formal_cas().resolve_reference(child_locator)
                child_proof = self._formal_cas().verify_existing(child_object)
                child_raw = self._formal_cas().open_verified(child_object)
            except Exception as error:
                raise AuthorityError("Forge child authorization CAS proof cannot be reopened") from error
            if (
                child_proof.object_ref.reference_id != child_locator
                or child_proof.object_ref.object_id != child_locator.removeprefix("cas:")
                or child_proof.purpose_class != "true-multi-agent-child-execution-authorization"
                or child_proof.fresh_verified is not True
                or child_proof.no_replace_published is not True
            ):
                raise AuthorityError("Forge child authorization CAS proof purpose or ownership is invalid")
            if child_object.plaintext_commitment != child.get("authorization_receipt_hash"):
                raise AuthorityError("Forge child authorization CAS commitment changed")
            if child_object.object_id != child_locator.removeprefix("cas:"):
                raise AuthorityError("Forge child authorization CAS object identity changed")
            try:
                child_body = parse_canonical_json(child_raw)
            except Exception as error:
                raise AuthorityError("Forge child authorization CAS body is not canonical") from error
            if not isinstance(child_body, Mapping) or child_body.get("schema") != "SITINA_EXECUTION_CHILD_AUTHORIZATION_V1":
                raise AuthorityError("Forge child authorization CAS schema is invalid")
            expected_child_body = {
                "schema": "SITINA_EXECUTION_CHILD_AUTHORIZATION_V1",
                "parent_authorization_hash": child.get("parent_authorization_hash"),
                "parent_run_id": child.get("run_id"),
                "run_id": child.get("child_run_id"),
                "attempt": child.get("run_attempt"),
                "purpose": "forge-attempt",
                "session_instance_id": child.get("session_instance_id"),
                "conversation_session_id": child.get("conversation_session_id"),
                "turn_index": child.get("turn_index"),
                "generation": child.get("generation"),
                "session_id": child.get("conversation_session_id"),
                "intent_hash": current_execution_auth.get("intent_hash"),
                "workspace": child.get("workspace"),
                "execution_root": child.get("execution_root"),
                "scope": child.get("scope"),
                "risk_level": child.get("risk_level"),
                "provider_profile": child.get("provider_profile"),
                "provider_model": child.get("provider_model"),
                "expires_at": child.get("expires_at"),
                "authorization_ref": child.get("authorization_ref"),
                "payload_hash": child.get("payload_hash"),
                "authorization_hash": child.get("payload_hash"),
            }
            # intent_hash is a parent-owned field that is not duplicated in
            # the Journal child event.  It must still be present in the
            # authenticated CAS body and remain stable across the event/CAS
            # binding, rather than being silently ignored.
            if not isinstance(expected_child_body["intent_hash"], str) or not expected_child_body["intent_hash"]:
                raise AuthorityError("Forge child authorization CAS intent binding is missing")
            if set(child_body) != set(expected_child_body) or canonical_json_bytes(dict(child_body)) != canonical_json_bytes(expected_child_body):
                raise AuthorityError("Forge child authorization CAS binding changed")
            prior_scope = session.get("pre_provider_scope") or session.get("forge_transport_scope")
            if not isinstance(prior_scope, Mapping) or prior_scope.get("run_id") != root_run_id:
                raise AuthorityError("Forge transport binding lacks a prior admitted provider scope")
            authorization_id = "forge-execution:" + hashlib.sha256(_canonical({
                "child_authorization_locator": child_locator,
                "run_id": root_run_id, "run_attempt": child["run_attempt"],
                "authorization_ref": child["authorization_ref"],
            })).hexdigest()
            session["transport_authorization_id"] = authorization_id
            session["transport_authorization_kind"] = "forge-execution"
            session["transport_authorization_domain"] = "attempt_execution"
            session["forge_transport_scope"] = {
                "run_id": root_run_id, "run_attempt": child["run_attempt"],
                "authorization_ref": child.get("authorization_ref"),
                "child_authorization_locator": child_locator,
                "parent_authorization_ref": child.get("parent_authorization_ref"),
                "session_instance_id": child.get("session_instance_id"),
                "generation": child.get("generation"),
                "provider_profile": child.get("provider_profile"),
                "provider_model": child.get("provider_model"),
                "issued_at": prior_scope.get("issued_at"),
                "expires_at": child.get("expires_at"),
            }
            execution_record = {
                "authorization_id": authorization_id,
                "authorization": dict(session["forge_transport_scope"]),
                "child_authorization_locator": child_locator,
            }
            domains = session.setdefault("authorization_domains", {})
            domains.setdefault("attempt_execution_by_attempt", {})[(root_run_id, int(child["run_attempt"]))] = execution_record
            # This is only the active request projection.  Historical
            # attempt mappings remain addressable in the keyed registry.
            domains["attempt_execution"] = execution_record
            return {
                "bound": True, "authorization_id": authorization_id,
                "authorization_ref": child.get("authorization_ref"),
                "parent_authorization_ref": child.get("parent_authorization_ref"),
                "child_authorization_locator": child_locator,
                "run_attempt": child.get("run_attempt"),
                "run_id": root_run_id,
                "child_run_id": child.get("child_run_id"),
                "provider_profile": child.get("provider_profile"),
                "provider_model": child.get("provider_model"),
            }
        if method == "transport_bind_attempt_control":
            if set(request) != {"method", "session", "capability"}:
                raise AuthorityError("attempt-control binding accepts no caller facts")
            if request.get("capability") != session.get("transport_capability"):
                raise AuthorityError("transport capability is invalid")
            domains = session.setdefault("authorization_domains", {})
            forge_scope = session.get("forge_transport_scope")
            if not isinstance(forge_scope, Mapping):
                raise AuthorityError("attempt-control binding requires Forge execution")
            root_run_id = str(forge_scope.get("run_id") or "")
            snapshot = self._journal_snapshot()
            current_attempt, current_ref, current_auth = self._latest_attempt_binding(snapshot, root_run_id)
            current_execution_auth = self._current_execution_authorization(
                current_attempt, current_auth,
            )
            if current_attempt != int(forge_scope.get("run_attempt") or 0):
                raise AuthorityError("attempt-control binding uses a stale attempt")
            current_parent_ref = str(forge_scope.get("parent_authorization_ref") or "")
            forge_ref = str(forge_scope.get("authorization_ref") or "")
            if not current_parent_ref or not forge_ref or current_ref != current_parent_ref:
                raise AuthorityError("attempt-control parent authorization is stale")
            # Only the exact current (root run, attempt) record may be
            # replayed.  The active flat alias is a transport projection and
            # is never a lookup authority; otherwise a prior run/attempt
            # could be returned before the current Journal chain is checked.
            current_key = (root_run_id, current_attempt)
            by_attempt = domains.get("attempt_control_by_attempt") if isinstance(domains, Mapping) else None
            prior = by_attempt.get(current_key) if isinstance(by_attempt, Mapping) else None
            if isinstance(prior, Mapping):
                prior_auth = prior.get("authorization")
                if not isinstance(prior_auth, Mapping):
                    raise AuthorityError("attempt-control mapping is invalid")
                if (
                    prior.get("authorization_id") != "attempt-control:" + hashlib.sha256(_canonical(prior_auth)).hexdigest()
                    or prior_auth.get("run_id") != root_run_id
                    or prior_auth.get("run_attempt") != current_attempt
                    or prior_auth.get("authorization_ref") != current_ref
                    or prior_auth.get("parent_execution_authorization_ref") != forge_ref
                ):
                    raise AuthorityError("attempt-control mapping is not the current exact record")
                domains["attempt_control"] = prior
                session["transport_authorization_id"] = str(prior["authorization_id"])
                session["transport_authorization_kind"] = "attempt-control"
                session["transport_authorization_domain"] = "attempt_control"
                return {"bound": True, "authorization_id": prior.get("authorization_id"), **dict(prior_auth)}
            try:
                projected = attempt_control_authorization_projection(
                    session_instance_id=str(current_execution_auth.get("session_instance_id") or ""),
                    conversation_session_id=str(current_execution_auth.get("session_id") or ""),
                    turn_index=int(current_execution_auth.get("turn_index") or 0),
                    run_id=root_run_id,
                    run_attempt=current_attempt,
                    generation=str(current_execution_auth.get("generation") or ""),
                    authorization_ref=current_ref,
                    parent_execution_authorization_ref=forge_ref,
                    provider_profile=str(forge_scope.get("provider_profile") or ""),
                    provider_model=str(forge_scope.get("provider_model") or ""),
                    expires_at=int(forge_scope.get("expires_at") or 0),
                )
            except Exception as error:
                raise AuthorityError("attempt-control facts are incomplete") from error
            authorization_id = "attempt-control:" + hashlib.sha256(_canonical(projected)).hexdigest()
            control_record = {
                "authorization_id": authorization_id,
                "authorization": dict(projected),
            }
            domains.setdefault("attempt_control_by_attempt", {})[current_key] = control_record
            domains["attempt_control"] = control_record
            session["transport_authorization_id"] = authorization_id
            session["transport_authorization_kind"] = "attempt-control"
            session["transport_authorization_domain"] = "attempt_control"
            return {"bound": True, "authorization_id": authorization_id, **projected}
        if method in {"validate_canary", "consume_canary", "transport_bind_canary"}:
            auth = request.get("authorization")
            record = self._canaries.get(str(auth.get("authorization_id"))) if isinstance(auth, Mapping) else None
            expected = record.get("authorization") if isinstance(record, Mapping) else None
            if (not isinstance(record, Mapping) or record.get("session") != session_token or record.get("consumed")
                    or not isinstance(expected, Mapping) or dict(auth) != dict(expected)
                    or int(auth.get("expires_at") or 0) <= int(time.time())):
                raise AuthorityError("canary authorization is invalid")
            if method == "transport_bind_canary":
                session["transport_authorization_id"] = str(auth["authorization_id"])
                session["transport_authorization_kind"] = "canary"
                session["transport_authorization_domain"] = "post_review_canary"
                session.setdefault("authorization_domains", {})["post_review_canary"] = {
                    "authorization_id": str(auth["authorization_id"]),
                    "authorization": dict(expected),
                }
                return {"bound": True}
            if method == "consume_canary":
                record["consumed"] = True
            return {"valid": True}
        if method == "transport_begin":
            if request.get("capability") != session.get("transport_capability"):
                raise AuthorityError("transport capability is invalid")
            max_retries = request.get("max_retries", 0)
            physical_attempt_budget = request.get(
                "physical_attempt_budget",
                1 + int(max_retries) if type(max_retries) is int else 0,
            )
            if (
                type(max_retries) is not int or not 0 <= max_retries <= 3
                or type(physical_attempt_budget) is not int
                or physical_attempt_budget != 1 + max_retries
            ):
                raise AuthorityError("provider retry budget is not an exact bounded commitment")
            authorization_domain = request.get("authorization_domain") or session.get("transport_authorization_domain")
            if authorization_domain is None:
                authorization_domain = {
                    "pre-provider": "pre_provider_root",
                    "forge-execution": "attempt_execution",
                    "canary": "post_review_canary",
                }.get(session.get("transport_authorization_kind"))
            if authorization_domain not in {"pre_provider_root", "attempt_execution", "attempt_control", "post_review_canary"}:
                raise AuthorityError("transport authorization domain is invalid")
            domain_record = (session.get("authorization_domains") or {}).get(authorization_domain)
            authorization_id = domain_record.get("authorization_id") if isinstance(domain_record, Mapping) else session.get("transport_authorization_id")
            authorization = None
            authorization_kind = {
                "pre_provider_root": "pre-provider",
                "attempt_execution": "forge-execution",
                "attempt_control": "attempt-control",
                "post_review_canary": "canary",
            }[authorization_domain]
            if authorization_id:
                if authorization_kind == "pre-provider":
                    record = self._pre_provider_authorizations.get(str(authorization_id))
                elif authorization_kind == "forge-execution":
                    scope = session.get("forge_transport_scope")
                    if not isinstance(scope, Mapping):
                        raise AuthorityError("Forge transport binding is missing")
                    authorization = {
                        "authorization_id": authorization_id,
                        "run_id": scope.get("run_id"),
                        "run_attempt": scope.get("run_attempt"),
                        "authorization_ref": scope.get("authorization_ref"),
                        "parent_authorization_ref": scope.get("parent_authorization_ref"),
                        "child_authorization_locator": scope.get("child_authorization_locator"),
                        "session_instance_id": scope.get("session_instance_id"),
                        "generation": scope.get("generation"),
                        "provider_profile": scope.get("provider_profile"),
                        "provider_model": scope.get("provider_model"),
                        "issued_at": scope.get("issued_at"),
                        "expires_at": scope.get("expires_at"),
                    }
                    record = {"session": session_token, "authorization": authorization}
                elif authorization_kind == "attempt-control":
                    scope = domain_record.get("authorization") if isinstance(domain_record, Mapping) else None
                    if not isinstance(scope, Mapping):
                        raise AuthorityError("attempt-control transport binding is missing")
                    authorization = dict(scope)
                    authorization["authorization_id"] = authorization_id
                    record = {"session": session_token, "authorization": authorization}
                else:
                    record = self._canaries.get(str(authorization_id))
                if authorization_kind != "forge-execution":
                    authorization = record.get("authorization") if isinstance(record, Mapping) else None
                if (
                    not isinstance(record, Mapping) or record.get("session") != session_token
                    or (authorization_kind != "pre-provider" and record.get("consumed"))
                    or not isinstance(authorization, Mapping)
                    or int(authorization.get("expires_at") or 0) <= int(time.time())
                    or request.get("authorization_id") != authorization_id
                    or request.get("authorization_kind", authorization_kind) != authorization_kind
                    or request.get("authorization_domain", authorization_domain) != authorization_domain
                ):
                    raise AuthorityError("transport authorization binding is invalid")
                requested_run = str(request.get("run_id") or "")
                root_run = str(authorization.get("run_id") or "")
                if authorization_kind == "pre-provider":
                    if "attempt_execution" in (session.get("authorization_domains") or {}):
                        raise AuthorityError("pre-provider root authorization is not valid after Forge bind")
                    if requested_run != root_run or requested_run.startswith("forge-exec-"):
                        raise AuthorityError("pre-provider authorization cannot authorize Forge or another run")
                    derived_attempt = int(authorization.get("run_attempt") or 0)
                    current_snapshot = self._journal_snapshot()
                    dispatch = self._require_root_dispatch(current_snapshot, root_run, request)
                    phase = dispatch.get("phase")
                    role = dispatch.get("role")
                    call_index = dispatch.get("call_index")
                    v2_fields = {
                        "agent_id": dispatch.get("agent_id"),
                        "task_id": dispatch.get("task_id"),
                        "dispatch_commitment": dispatch.get("dispatch_commitment"),
                        "predecessor_identity": dispatch.get("predecessor_identity"),
                    }
                    if (
                        phase not in CODE_MODE_PRE_PROVIDER_PHASES
                        or not isinstance(role, str) or not role
                        or type(call_index) is not int or call_index < 1
                        or any(not isinstance(value, str) or not value for value in v2_fields.values())
                    ):
                        raise AuthorityError("authenticated root dispatch is incomplete")
                    expected_identity = provider_call_identity_v2(
                        session_instance_id=authorization["session_instance_id"],
                        conversation_session_id=authorization["conversation_session_id"],
                        turn_index=authorization["turn_index"], run_id=root_run,
                        run_attempt=derived_attempt, agent_id=v2_fields["agent_id"],
                        task_id=v2_fields["task_id"],
                        dispatch_commitment=v2_fields["dispatch_commitment"],
                        predecessor_identity=v2_fields["predecessor_identity"],
                        phase=phase, role=role, call_index=call_index,
                        provider_profile=authorization["provider_profile"],
                        provider_model=authorization["provider_model"],
                    )
                    if dispatch.get("pre_provider_call_identity") != expected_identity:
                        raise AuthorityError("authenticated root dispatch identity is not deterministic")
                    provider_call_id = dispatch.get("provider_call_id")
                    prior_provider_call = (session.get("provider_calls") or {}).get(provider_call_id)
                    # A root planning call owns one physical permit at a
                    # time.  A PREPARED record is the only retryable state
                    # (the preceding host attempt returned an explicitly
                    # retryable HTTP status); a direct duplicate begin must
                    # not mint a second permit before the first call settles.
                    if isinstance(prior_provider_call, Mapping) and prior_provider_call.get("state") in {
                        "SEND_STARTED", "SETTLED", "OUTCOME_UNKNOWN",
                    }:
                        raise AuthorityError("root provider call already has a live or terminal permit")
                    root_state = self._root_fsm_from_snapshot(current_snapshot, root_run)
                    if root_state == "CLOSED_REJECTED":
                        raise AuthorityError(
                            "root planning is closed after rejected revision",
                            reason_code="ROOT_REWORK_CLOSED_REJECTED",
                        )
                    if root_state in {"WAIT_SELECTION", "ROOT_COMPLETE"}:
                        raise AuthorityError("root planning is closed for new provider permits")
                    retry_in_progress = isinstance(prior_provider_call, Mapping) and prior_provider_call.get("state") == "PREPARED"
                    if not retry_in_progress:
                        if any(
                            isinstance(item, Mapping)
                            and item.get("state") == "OUTCOME_UNKNOWN"
                            for item in (session.get("provider_calls") or {}).values()
                        ):
                            raise AuthorityError("root planning is blocked by an unknown Provider outcome")
                        settled = self._root_fact_events(
                            current_snapshot, root_run, "CODE_MODE_ROOT_SETTLED_FACT_V1",
                            "code-mode.root-call-settled",
                        )
                        if call_index != len(settled) + 1:
                            raise AuthorityError("root planning call index is not the exact next transition")
                        if root_state == "EXPECT_DISCOVERY":
                            if phase == CODE_MODE_FAST_PRE_PROVIDER_PHASE:
                                if request.get("task_id") != "conversation-answer" or call_index != 1:
                                    raise AuthorityError("FAST root planning must be one conversation synthesis call")
                            elif phase != "discovery/controller":
                                raise AuthorityError("root planning must begin with discovery")
                        if root_state == "EXPECT_PROPOSAL" and phase != "proposal/planner/candidate":
                            raise AuthorityError("root planning requires a proposal before review")
                        if root_state == "EXPECT_REVIEW" and phase != "review/selection":
                            raise AuthorityError("root planning requires review before selection")
                        if root_state in {"EXPECT_REVISION", "EXPECT_REVISION_REVIEW"}:
                            rework = self._root_proposal_rework_state(current_snapshot, root_run)
                            if not isinstance(rework, Mapping) or rework.get("state") != root_state:
                                raise AuthorityError(
                                    "proposal rework transition is stale or contradictory",
                                    reason_code="ROOT_REWORK_STALE_TRANSITION",
                                )
                            expected_phase = (
                                "proposal/planner/candidate"
                                if root_state == "EXPECT_REVISION" else "review/selection"
                            )
                            expected_prefix = (
                                "proposal-revision-"
                                if root_state == "EXPECT_REVISION" else "review-revision-"
                            )
                            if (
                                phase != expected_phase
                                or not str(request.get("task_id") or "").startswith(expected_prefix)
                            ):
                                raise AuthorityError(
                                    "proposal rework task is outside the fixed transition",
                                    reason_code="ROOT_REWORK_TASK_BINDING_INVALID",
                                )
                            if root_state == "EXPECT_REVISION":
                                if (
                                    dispatch.get("agent_id") != rework.get("author_id")
                                    or request.get("task_id") != "proposal-revision-1"
                                ):
                                    raise AuthorityError(
                                        "proposal revision author or budget changed",
                                        reason_code="ROOT_REWORK_AUTHOR_BINDING_INVALID",
                                    )
                            else:
                                if (
                                    dispatch.get("agent_id") != rework.get("reviewer_id")
                                    or request.get("task_id") != "review-revision-1"
                                ):
                                    raise AuthorityError(
                                        "proposal second reviewer or successor changed",
                                        reason_code="ROOT_REWORK_REVIEWER_BINDING_INVALID",
                                    )
                    if request.get("pre_provider_call_identity") != expected_identity:
                        raise AuthorityError("pre-provider call identity is not deterministic")
                elif authorization_kind == "forge-execution":
                    expected_run = f"forge-exec-{root_run}-{int(authorization.get('run_attempt') or 0)}"
                    if requested_run != expected_run:
                        raise AuthorityError("Forge transport run is outside the current execution mapping")
                    derived_attempt = int(authorization.get("run_attempt") or 0)
                    if request.get("execution_authorization_ref") != authorization.get("authorization_ref"):
                        raise AuthorityError("Forge transport authorization ref is stale")
                else:
                    if requested_run != root_run and not requested_run.startswith(f"forge-exec-{root_run}-"):
                        raise AuthorityError("transport run is outside authorization")
                    derived_attempt = int(authorization.get("run_attempt") or 0) if requested_run == root_run else int(requested_run.rsplit("-", 1)[-1])
                if request.get("attempt", derived_attempt) != derived_attempt:
                    raise AuthorityError("transport attempt binding is invalid")
                current_snapshot = self._journal_snapshot()
                if authorization_kind == "pre-provider":
                    has_attempt_chain = any(
                        frame.transaction.stream_id == f"run/{root_run}"
                        and any(
                            isinstance(event.payload, Mapping)
                            and event.payload.get("event_type") in {
                                "execution.authorization.bound",
                                "execution.authorization.attempt_advanced",
                            }
                            for event in frame.transaction.events
                        )
                        for frame in current_snapshot
                    )
                    if has_attempt_chain:
                        current_attempt, current_ref, current_auth = self._latest_attempt_binding(
                            current_snapshot, root_run
                        )
                    else:
                        current_attempt, current_ref, current_auth = self._run_created_binding(
                            current_snapshot, root_run,
                            pre_provider_scope=session.get("pre_provider_scope"),
                        )
                else:
                    current_attempt, current_ref, current_auth = self._latest_attempt_binding(
                        current_snapshot, root_run
                    )
                if authorization_kind == "pre-provider":
                    if current_attempt != derived_attempt:
                        raise AuthorityError("pre-provider permit uses a stale execution attempt")
                    if current_auth.get("session_instance_id") != authorization.get("session_instance_id"):
                        raise AuthorityError("pre-provider session instance changed")
                    if current_auth.get("generation") != authorization.get("generation"):
                        raise AuthorityError("pre-provider generation changed")
                elif authorization_kind == "forge-execution" and (current_attempt != derived_attempt or current_ref != authorization.get("parent_authorization_ref")):
                    raise AuthorityError("transport permit uses a stale execution authorization")
                elif authorization_kind == "attempt-control" and (current_attempt != derived_attempt or current_ref != authorization.get("authorization_ref")):
                    raise AuthorityError("attempt-control authorization is stale")
                elif authorization_kind == "canary" and current_attempt != derived_attempt:
                    raise AuthorityError("canary authorization uses a stale execution attempt")
                if current_auth.get("session_instance_id") != authorization.get("session_instance_id"):
                    raise AuthorityError("transport session instance changed")
                if current_auth.get("generation") != authorization.get("generation"):
                    raise AuthorityError("transport generation changed")
                if request.get("provider_profile") != authorization.get("provider_profile"):
                    raise AuthorityError("transport provider profile binding changed")
                if request.get("provider_model") != authorization.get("provider_model"):
                    raise AuthorityError("transport provider model binding changed")
            else:
                raise AuthorityError("authoritative transport requires a bound canary authorization")
            self._next_sequence += 1
            permit = secrets.token_urlsafe(24)
            prior_call: Mapping[str, Any] = {
                "retry_count": 0,
                "physical_attempts": 0,
            }
            if authorization_kind == "pre-provider":
                provider_calls = session.setdefault("provider_calls", {})
                existing_call = provider_calls.get(str(provider_call_id or ""))
                if not isinstance(existing_call, Mapping):
                    existing_call = {
                        "provider_call_id": str(provider_call_id),
                        "state": "SEND_STARTED",
                    }
                    provider_calls[str(provider_call_id)] = existing_call
                elif existing_call.get("state") == "PREPARED":
                    existing_call["state"] = "SEND_STARTED"
                prior_call = existing_call
            self._pending[permit] = {"session": session_token, "authorization_id": str(authorization_id or ""),
                "authorization_kind": authorization_kind,
                "provider_call_id": str(request.get("provider_call_id") or ""),
                "candidate_id": str(authorization.get("candidate_id") or "") if authorization else "",
                "run_id": str(request.get("run_id") or ""), "attempt": derived_attempt,
                "effect_attempt_id": str(request.get("effect_attempt_id") or ""), "physical_sequence": self._next_sequence,
                "provider_profile": str(request.get("provider_profile") or ""), "provider_model": str(request.get("provider_model") or ""),
                "execution_authorization_ref": str(authorization.get("authorization_ref") or ""),
                "max_retries": max_retries, "physical_attempt_budget": physical_attempt_budget,
                "retry_count": int(prior_call.get("retry_count") or 0),
                "physical_attempts": int(prior_call.get("physical_attempts") or 0),
                "snapshot_hash": self._snapshot_hash(current_snapshot)}
            return {"permit": permit}
        if method == "transport_settle":
            raise AuthorityError("worker-side transport settlement is forbidden")
        if method == "transport_send":
            profile_name = str(request.get("provider_profile") or "")
            profile = self._profiles.get(profile_name)
            if not isinstance(profile, Mapping):
                raise AuthorityError("host has no authorized provider profile")
            if str(profile.get("model") or "") != str(request.get("provider_model") or ""):
                raise AuthorityError("provider model binding changed")
            system_prompt = request.get("system_prompt")
            messages = request.get("messages")
            tools = request.get("tools")
            user_prompt = request.get("user_prompt")
            if not isinstance(system_prompt, str):
                raise AuthorityError("host transport payload is incomplete")
            if hashlib.sha256(system_prompt.encode()).hexdigest() != str(request.get("system_prompt_hash") or ""):
                raise AuthorityError("system prompt hash mismatch")
            if isinstance(messages, list):
                if hashlib.sha256(_canonical(messages)).hexdigest() != str(request.get("messages_hash") or ""):
                    raise AuthorityError("messages binding hash mismatch")
            elif not isinstance(user_prompt, str):
                raise AuthorityError("host transport messages are incomplete")
            structured_response = request.get("structured_response") is True
            if structured_response:
                if request.get("structured_response_tool_name") != STRUCTURED_RESPONSE_TOOL_NAME:
                    raise AuthorityError("structured response tool name binding is invalid")
                if type(tools) is not list or len(tools) != 1:
                    raise AuthorityError("structured response requires one native tool")
                tool = tools[0]
                function = tool.get("function") if isinstance(tool, Mapping) else None
                if (
                    not isinstance(tool, Mapping)
                    or set(tool) != {"type", "function"}
                    or tool.get("type") != "function"
                    or not isinstance(function, Mapping)
                    or set(function) != {"name", "description", "parameters"}
                    or function.get("name") != STRUCTURED_RESPONSE_TOOL_NAME
                ):
                    raise AuthorityError("structured response tool binding is invalid")
            elif not isinstance(tools, list):
                tools = []
            if hashlib.sha256(_canonical(tools)).hexdigest() != str(request.get("tools_hash") or ""):
                raise AuthorityError("tools binding hash mismatch")
            provider_call_id = request.get("provider_call_id")
            if not isinstance(provider_call_id, str) or not provider_call_id:
                raise AuthorityError("provider call identity is required")
            max_retries = request.get("max_retries", 0)
            physical_attempt_budget = request.get(
                "physical_attempt_budget",
                1 + int(max_retries) if type(max_retries) is int else 0,
            )
            if (
                type(max_retries) is not int or not 0 <= max_retries <= 3
                or type(physical_attempt_budget) is not int
                or physical_attempt_budget != 1 + max_retries
            ):
                raise AuthorityError("provider retry budget is not an exact bounded commitment")
            # The request commitment contains only stable, non-secret request
            # identities.  Prompt bodies are represented by their already
            # authenticated hashes; raw prompt text never enters the replay
            # ledger.  This is the durable logical-call identity used for
            # settled/lost-ack replay, distinct from the physical permit.
            call_commitment = _hash({
                "provider_call_id": provider_call_id,
                "effect_attempt_id": request.get("effect_attempt_id"),
                "run_id": request.get("run_id"),
                "attempt": request.get("attempt"),
                "authorization_id": request.get("authorization_id"),
                "authorization_domain": request.get("authorization_domain"),
                "authorization_kind": request.get("authorization_kind"),
                "execution_authorization_ref": request.get("execution_authorization_ref"),
                "provider_profile": profile_name,
                "provider_model": request.get("provider_model"),
                "system_prompt_hash": request.get("system_prompt_hash"),
                "user_prompt_hash": request.get("user_prompt_hash"),
                "messages_hash": request.get("messages_hash"),
                "tools_hash": request.get("tools_hash"),
                "structured_response": structured_response,
                "structured_response_tool_name": request.get("structured_response_tool_name"),
                "max_tokens": request.get("max_tokens"),
                "phase": request.get("phase"),
                "role": request.get("role"),
                "call_index": request.get("call_index"),
                "pre_provider_call_identity": request.get("pre_provider_call_identity"),
                "agent_id": request.get("agent_id"),
                "task_id": request.get("task_id"),
                "scheduling_task_id": request.get("scheduling_task_id"),
                "scheduling_decision_id": request.get("scheduling_decision_id"),
                "scheduling_decision_commitment": request.get("scheduling_decision_commitment"),
                "dispatch_command_id": request.get("dispatch_command_id"),
                "dispatch_command_commitment": request.get("dispatch_command_commitment"),
                "selected_agent_id": request.get("selected_agent_id"),
                "slot": request.get("slot"),
                "dispatch_commitment": request.get("dispatch_commitment"),
                "predecessor_identity": request.get("predecessor_identity"),
                "max_retries": max_retries,
                "physical_attempt_budget": physical_attempt_budget,
            })
            provider_calls = session.setdefault("provider_calls", {})
            prior_call = provider_calls.get(provider_call_id)
            if isinstance(prior_call, Mapping):
                if prior_call.get("commitment") != call_commitment:
                    raise AuthorityError("provider call identity is bound to a different request")
                state = prior_call.get("state")
                if state == "SETTLED":
                    replay = prior_call.get("response")
                    if isinstance(replay, Mapping):
                        return dict(replay)
                    raise AuthorityError("settled provider call has no durable response")
                if state == "OUTCOME_UNKNOWN":
                    raise AuthorityError("provider call outcome is unknown; blind resend is forbidden")
            else:
                prior_call = {
                    "provider_call_id": provider_call_id,
                    "commitment": call_commitment,
                    "state": "PREPARED",
                    "retry_count": 0,
                    "physical_attempts": 0,
                    "max_retries": max_retries,
                    "physical_attempt_budget": physical_attempt_budget,
                }
                provider_calls[provider_call_id] = prior_call
            if (
                prior_call.get("max_retries") != max_retries
                or prior_call.get("physical_attempt_budget") != physical_attempt_budget
            ):
                raise AuthorityError("provider retry budget changed for the logical call")
            if prior_call.get("state") == "RETRY_EXHAUSTED":
                raise AuthorityError("provider retry budget is exhausted")
            physical_attempts_so_far = prior_call.get("physical_attempts", 0)
            if type(physical_attempts_so_far) is not int or physical_attempts_so_far >= physical_attempt_budget:
                prior_call["state"] = "RETRY_EXHAUSTED"
                raise AuthorityError("provider retry budget is exhausted")
            permit = self.dispatch({
                "method": "transport_begin", "session": session_token,
                "capability": request.get("capability"), "authorization_id": request.get("authorization_id"),
                "authorization_kind": request.get("authorization_kind"),
                "run_id": request.get("run_id"), "attempt": request.get("attempt", 0),
                "effect_attempt_id": request.get("effect_attempt_id"), "provider_profile": profile_name,
                "provider_model": request.get("provider_model"),
                "session_instance_id": request.get("session_instance_id"),
                "conversation_session_id": request.get("conversation_session_id"),
                "turn_index": request.get("turn_index"),
                "generation": request.get("generation"),
                "phase": request.get("phase"), "role": request.get("role"),
                "call_index": request.get("call_index"),
                "pre_provider_call_identity": request.get("pre_provider_call_identity"),
                "agent_id": request.get("agent_id"), "task_id": request.get("task_id"),
                "scheduling_task_id": request.get("scheduling_task_id"),
                "scheduling_decision_id": request.get("scheduling_decision_id"),
                "scheduling_decision_commitment": request.get("scheduling_decision_commitment"),
                "dispatch_command_id": request.get("dispatch_command_id"),
                "dispatch_command_commitment": request.get("dispatch_command_commitment"),
                "selected_agent_id": request.get("selected_agent_id"),
                "slot": request.get("slot"),
                "dispatch_commitment": request.get("dispatch_commitment"),
                "predecessor_identity": request.get("predecessor_identity"),
                "authorization_domain": request.get("authorization_domain"),
                "execution_authorization_ref": request.get("execution_authorization_ref"),
                "provider_call_id": provider_call_id,
                "max_retries": max_retries,
                "physical_attempt_budget": physical_attempt_budget,
            })["permit"]
            pending = self._pending.get(permit)
            if not isinstance(pending, dict):
                raise AuthorityError("transport permit state is missing")
            pending.update({
                "max_retries": max_retries,
                "physical_attempt_budget": physical_attempt_budget,
                "retry_count": int(prior_call.get("retry_count") or 0),
                "physical_attempts": int(physical_attempts_so_far),
            })
            prior_call["state"] = "SEND_STARTED"
            prior_call["permit"] = permit
            base_url = str(profile.get("base_url") or "").rstrip("/")
            if not _provider_endpoint_allowed(base_url, profile):
                raise AuthorityError("host transport endpoint is outside the profile allowlist")
            protocol = _profile_wire_protocol(profile)
            if protocol == OPENAI_CHAT_COMPLETIONS:
                provider_messages = [
                    {"role": "system", "content": system_prompt},
                    *_provider_messages(messages, user_prompt, OPENAI_CHAT_COMPLETIONS),
                ]
                body = {"model": profile["model"], "max_tokens": int(request.get("max_tokens") or 0),
                        "temperature": 0.0, "messages": provider_messages}
                try:
                    body["tools"] = provider_tools_for_wire(tools, OPENAI_CHAT_COMPLETIONS)
                except ProviderError as error:
                    raise AuthorityError("provider tools are malformed") from error
                if structured_response:
                    body.update({
                        "tool_choice": {
                            "type": "function",
                            "function": {"name": STRUCTURED_RESPONSE_TOOL_NAME},
                        },
                    })
                    if "deepseek_thinking_disabled" in _profile_adapter_capabilities(profile):
                        body["thinking"] = {"type": "disabled"}
                elif not tools:
                    body["response_format"] = {"type": "json_object"}
                request_url = base_url + "/chat/completions" if not base_url.endswith("/chat/completions") else base_url
                headers = {"content-type": "application/json", "accept": "application/json", "authorization": "Bearer " + str(profile.get("auth_token") or "")}
            elif protocol == ANTHROPIC_MESSAGES:
                body = {
                    "model": profile["model"],
                    "max_tokens": int(request.get("max_tokens") or 0),
                    "system": system_prompt,
                    "messages": _provider_messages(messages, user_prompt, ANTHROPIC_MESSAGES),
                }
                if tools:
                    body["tools"] = _anthropic_tools(tools)
                if structured_response:
                    body["tool_choice"] = {"type": "tool", "name": STRUCTURED_RESPONSE_TOOL_NAME}
                request_url = base_url if base_url.endswith("/messages") else (base_url + "/messages" if base_url.endswith("/v1") else base_url + "/v1/messages")
                headers = {
                    "content-type": "application/json", "accept": "application/json",
                    "anthropic-version": "2023-06-01", "x-api-key": str(profile.get("auth_token") or ""),
                }
            else:
                raise AuthorityError("host transport profile has an unsupported protocol")
            # The provider wire format permits the protocol's numeric
            # temperature field.  The Journal/CAS identity canonicalizer is
            # intentionally stricter (no floats), so serialization of the
            # outbound HTTP body must remain separate from evidence hashing.
            wire_body = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            try:
                # Consume the host-owned physical attempt immediately before
                # urlopen.  This is the only point at which an HTTP attempt
                # may be created, and the counter is included in the signed
                # receipt returned by _settle_pending.
                prior_call["physical_attempts"] = physical_attempts_so_far + 1
                pending["physical_attempts"] = int(prior_call["physical_attempts"])
                http_request = urllib.request.Request(request_url, data=wire_body, method="POST", headers=headers)
                with urllib.request.urlopen(http_request, timeout=float(request.get("timeout") or 60)) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as error:
                status_code = int(error.code)
                self._pending.pop(str(permit), None)
                # The host has already consumed the physical attempt before
                # ``urlopen``.  Persist that observed failed attempt even
                # though no usage-bearing response exists.  The receipt is
                # keyed by the immutable logical/attempt identity so a
                # replayed observation is idempotent and cannot mint a
                # second physical send or fabricate token usage.
                self._append_transport_failure_receipt(
                    session_token,
                    pending,
                    outcome_state="FAILED_CONFIRMED",
                    settlement_state="SETTLED",
                    status_code=status_code,
                    error_type="HTTPError",
                    reason_code=f"PROVIDER_HTTP_STATUS_{status_code}",
                )
                if status_code in {429, 503}:
                    prior_call["retry_count"] = int(prior_call.get("retry_count") or 0) + 1
                    prior_call["state"] = (
                        "RETRY_EXHAUSTED"
                        if int(prior_call.get("physical_attempts") or 0) >= int(prior_call.get("physical_attempt_budget") or 0)
                        or int(prior_call.get("retry_count") or 0) > int(prior_call.get("max_retries") or 0)
                        else "PREPARED"
                    )
                    raise AuthorityError(
                        f"HTTP_STATUS_{status_code}: host provider HTTP request failed",
                        status_code=status_code,
                        reason_code=f"PROVIDER_HTTP_STATUS_{status_code}",
                    ) from error
                prior_call["state"] = "OUTCOME_UNKNOWN"
                raise AuthorityError(
                    f"HTTP_STATUS_{status_code}: host provider HTTP request failed",
                    status_code=status_code,
                    reason_code=f"PROVIDER_HTTP_STATUS_{status_code}",
                ) from error
            except Exception as error:
                self._pending.pop(str(permit), None)
                prior_call["state"] = "OUTCOME_UNKNOWN"
                self._append_transport_failure_receipt(
                    session_token,
                    pending,
                    outcome_state="OUTCOME_UNKNOWN",
                    settlement_state="RECONCILING",
                    status_code=None,
                    error_type=type(error).__name__,
                    reason_code="PROVIDER_TRANSPORT_OUTCOME_UNKNOWN",
                )
                raise AuthorityError("host provider transport failed") from error
            return self._finalize_provider_response(
                session_token, request, payload, permit, prior_call,
            )
        if method == "transport_snapshot":
            if request.get("capability") != session.get("transport_capability"):
                raise AuthorityError("transport capability is invalid")
            return {"receipts": [dict(item) for item in self._transport[session_token]]}
        raise AuthorityError("unknown Code Mode host operation")

    def _finalize_provider_response(
        self,
        session_token: str,
        request: Mapping[str, Any],
        payload: Any,
        permit: str,
        prior_call: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate and settle one physical response.

        Once HTTP has been sent, every parse/schema/usage/tool/message failure
        is an unknown outcome.  Keeping this boundary separate makes that
        state transition unconditional and prevents a malformed 200 response
        from leaving a retryable PREPARED record.
        """
        profile = self._profiles.get(str(request.get("provider_profile") or ""))
        if isinstance(profile, Mapping) and _profile_wire_protocol(profile) == ANTHROPIC_MESSAGES:
            return self._finalize_anthropic_provider_response(
                session_token, request, payload, permit, prior_call,
            )
        settled = False
        try:
            if not isinstance(payload, Mapping):
                raise AuthorityError("host provider response is not a JSON object")
            choices = payload.get("choices")
            if type(choices) is not list or len(choices) != 1 or not isinstance(choices[0], Mapping):
                raise AuthorityError("host provider response choices are malformed")
            message = choices[0].get("message")
            if not isinstance(message, Mapping):
                raise AuthorityError("host provider response message is malformed")

            raw_tool_calls = message.get("tool_calls")
            if raw_tool_calls is not None and type(raw_tool_calls) is not list:
                raise AuthorityError("host provider response tool_calls must be an array or null")
            normalized_calls = []
            if isinstance(raw_tool_calls, list):
                for call in raw_tool_calls:
                    if not isinstance(call, Mapping) or set(call) not in (
                        {"id", "type", "function"}, {"id", "type", "function", "index"},
                    ):
                        raise AuthorityError("host provider response has malformed tool call")
                    if "index" in call and (type(call["index"]) is not int or call["index"] < 0):
                        raise AuthorityError("host provider tool call index is invalid")
                    call_id = call.get("id")
                    if type(call_id) is not str or not call_id:
                        raise AuthorityError("host provider tool call id is invalid")
                    if type(call.get("type")) is not str or call.get("type") != "function":
                        raise AuthorityError("host provider tool call type is invalid")
                    function = call.get("function")
                    if not isinstance(function, Mapping) or set(function) != {"name", "arguments"}:
                        raise AuthorityError("host provider tool function is not exact")
                    name = function.get("name")
                    arguments_raw = function.get("arguments")
                    if type(name) is not str or not name or type(arguments_raw) is not str or not arguments_raw:
                        raise AuthorityError("host provider tool function fields are invalid")
                    try:
                        arguments = json.loads(arguments_raw)
                    except (TypeError, json.JSONDecodeError) as error:
                        raise AuthorityError(
                            "host provider tool arguments are invalid",
                            reason_code="PROVIDER_TOOL_ARGUMENTS_INVALID_JSON",
                        ) from error
                    if not isinstance(arguments, Mapping):
                        raise AuthorityError("host provider tool arguments are not an object")
                    normalized_calls.append({"id": call_id, "name": name, "arguments": dict(arguments)})

            structured_response = request.get("structured_response") is True
            content_present = "content" in message
            content_value = message.get("content")
            if structured_response:
                if not (
                    content_present
                    and (
                        content_value is None
                        or (type(content_value) is str and content_value == "")
                    )
                ):
                    raise AuthorityError(
                        "structured response content must be explicit null or empty string"
                    )
            elif type(content_value) is not str:
                if not (
                    content_value is None
                    and bool(normalized_calls)
                    and content_present
                ):
                    raise AuthorityError("host provider response content is not a native string")
            content = content_value if type(content_value) is str else ""

            usage_raw = payload.get("usage")
            if not isinstance(usage_raw, Mapping):
                raise AuthorityError("host provider response has no token usage")
            usage_values = {
                "input_tokens": usage_raw.get("prompt_tokens"),
                "output_tokens": usage_raw.get("completion_tokens"),
                "total_tokens": usage_raw.get("total_tokens"),
            }
            if any(type(value) is not int or value < 0 for value in usage_values.values()):
                raise AuthorityError("host provider token usage has invalid native types")
            usage = dict(usage_values)
            if usage["total_tokens"] != usage["input_tokens"] + usage["output_tokens"]:
                raise AuthorityError("host provider token usage is inconsistent")
            response_id = payload.get("id")
            if type(response_id) is not str or not response_id:
                raise AuthorityError("host provider response has no native response identity")
            if structured_response:
                if len(normalized_calls) != 1 or normalized_calls[0]["name"] != STRUCTURED_RESPONSE_TOOL_NAME:
                    raise AuthorityError("structured response must contain exactly one fixed tool call")
                # Function arguments are the provider's native structured
                # result frame.  Re-canonicalize them before the strict
                # application ResultPipeline sees the bytes.
                content = canonical_json_bytes(normalized_calls[0]["arguments"]).decode("utf-8")
            # The provider protocol puts this field on the choice.  Do not
            # infer it from message/payload or silently turn omission into a
            # successful ``stop``; a structured result is only settled when
            # the native tool-call finish is explicit.
            finish_reason = choices[0].get("finish_reason")
            if type(finish_reason) is not str or not finish_reason:
                raise AuthorityError("host provider finish reason is invalid")
            if structured_response and finish_reason != "tool_calls":
                raise AuthorityError("structured response finish reason is not tool_calls")
            receipt = self._settle_pending(
                str(session_token), str(request.get("capability") or ""), str(permit),
                response_id, usage, finish_reason=finish_reason,
            )
            settled = True
            result = {"completion_text": content, "tool_calls": normalized_calls,
                    "stop_reason": finish_reason,
                    "metadata": {"protocol": "openai_chat_completions", "provider_response_id": response_id, "token_usage": usage, "finish_reason": finish_reason, "structured_response": structured_response}, "receipt": receipt}
            prior_call["state"] = "SETTLED"
            prior_call["response"] = dict(result)
            prior_call.pop("permit", None)
            return result
        except Exception as error:
            prior_call["state"] = "OUTCOME_UNKNOWN"
            # The HTTP request has already crossed the provider boundary at
            # this point.  If response parsing, schema validation, or usage
            # validation fails after a 200, preserve that physical attempt as
            # an issuer-owned OUTCOME_UNKNOWN receipt before dropping the
            # pending permit.  A successful settlement has its own durable
            # receipt and must never be shadowed by a failure receipt.
            reason_code = getattr(error, "reason_code", None) or "PROVIDER_RESPONSE_VALIDATION_FAILED"
            if not settled and str(permit) in self._pending:
                if not isinstance(reason_code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,96}", reason_code):
                    reason_code = "PROVIDER_RESPONSE_VALIDATION_FAILED"
                self._append_transport_failure_receipt(
                    session_token,
                    self._pending[str(permit)],
                    outcome_state="OUTCOME_UNKNOWN",
                    settlement_state="RECONCILING",
                    status_code=None,
                    error_type=type(error).__name__,
                    reason_code=reason_code,
                )
            self._pending.pop(str(permit), None)
            if isinstance(error, AuthorityError):
                if error.reason_code is None:
                    error.reason_code = reason_code
                raise
            raise AuthorityError(
                "host provider response validation failed",
                reason_code=reason_code,
            ) from error

    def _finalize_anthropic_provider_response(
        self,
        session_token: str,
        request: Mapping[str, Any],
        payload: Any,
        permit: str,
        prior_call: dict[str, Any],
    ) -> dict[str, Any]:
        """Validate Anthropic Messages and normalize it to Sitina's result."""

        settled = False
        try:
            if not isinstance(payload, Mapping):
                raise AuthorityError("host provider response is not a JSON object")
            response_id = payload.get("id")
            if type(response_id) is not str or not response_id:
                raise AuthorityError("host provider response has no native response identity")
            content = payload.get("content")
            if type(content) is not list:
                raise AuthorityError("Anthropic provider response content is malformed")
            text_parts: list[str] = []
            normalized_calls: list[dict[str, Any]] = []
            for block in content:
                if not isinstance(block, Mapping) or type(block.get("type")) is not str:
                    raise AuthorityError("Anthropic provider response content block is malformed")
                block_type = block["type"]
                if block_type == "text":
                    if set(block) != {"type", "text"} or type(block.get("text")) is not str:
                        raise AuthorityError("Anthropic text block is malformed")
                    text_parts.append(block["text"])
                elif block_type == "tool_use":
                    if set(block) != {"type", "id", "name", "input"}:
                        raise AuthorityError("Anthropic tool_use block is not exact")
                    if type(block.get("id")) is not str or not block["id"] or type(block.get("name")) is not str or not block["name"]:
                        raise AuthorityError("Anthropic tool_use identity is invalid")
                    if not isinstance(block.get("input"), Mapping):
                        raise AuthorityError("Anthropic tool_use input is not an object")
                    normalized_calls.append({
                        "id": block["id"], "name": block["name"], "arguments": dict(block["input"]),
                    })
                else:
                    raise AuthorityError("Anthropic provider response has an unsupported content block")
            structured_response = request.get("structured_response") is True
            finish_reason = payload.get("stop_reason")
            if type(finish_reason) is not str or not finish_reason:
                raise AuthorityError("Anthropic provider stop reason is invalid")
            if structured_response:
                if finish_reason != "tool_use" or len(normalized_calls) != 1 or normalized_calls[0]["name"] != STRUCTURED_RESPONSE_TOOL_NAME or text_parts:
                    raise AuthorityError("Anthropic structured response must contain exactly one tool_use")
                completion_text = canonical_json_bytes(normalized_calls[0]["arguments"]).decode("utf-8")
            else:
                completion_text = "".join(text_parts)
            usage_raw = payload.get("usage")
            if not isinstance(usage_raw, Mapping):
                raise AuthorityError("Anthropic provider response has no token usage")
            input_tokens, output_tokens = usage_raw.get("input_tokens"), usage_raw.get("output_tokens")
            if type(input_tokens) is not int or input_tokens < 0 or type(output_tokens) is not int or output_tokens < 0:
                raise AuthorityError("Anthropic provider token usage has invalid native types")
            usage = {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            }
            receipt = self._settle_pending(
                str(session_token), str(request.get("capability") or ""), str(permit),
                response_id, usage, finish_reason=finish_reason,
            )
            settled = True
            result = {
                "completion_text": completion_text,
                "tool_calls": normalized_calls,
                "stop_reason": finish_reason,
                "metadata": {
                    "protocol": ANTHROPIC_MESSAGES,
                    "provider_response_id": response_id,
                    "token_usage": usage,
                    "finish_reason": finish_reason,
                    "structured_response": structured_response,
                },
                "receipt": receipt,
            }
            prior_call["state"] = "SETTLED"
            prior_call["response"] = dict(result)
            prior_call.pop("permit", None)
            return result
        except Exception as error:
            prior_call["state"] = "OUTCOME_UNKNOWN"
            reason_code = getattr(error, "reason_code", None) or "PROVIDER_RESPONSE_VALIDATION_FAILED"
            if not settled and str(permit) in self._pending:
                if not isinstance(reason_code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,96}", reason_code):
                    reason_code = "PROVIDER_RESPONSE_VALIDATION_FAILED"
                self._append_transport_failure_receipt(
                    session_token,
                    self._pending[str(permit)],
                    outcome_state="OUTCOME_UNKNOWN",
                    settlement_state="RECONCILING",
                    status_code=None,
                    error_type=type(error).__name__,
                    reason_code=reason_code,
                )
            self._pending.pop(str(permit), None)
            if isinstance(error, AuthorityError):
                if error.reason_code is None:
                    error.reason_code = reason_code
                raise
            raise AuthorityError(
                "host provider response validation failed",
                reason_code=reason_code,
            ) from error

    def _settle_pending(
        self, session_token: str, capability: str, permit: str,
        response_id: str, usage: Mapping[str, Any], *, finish_reason: str,
    ) -> dict[str, Any]:
        session = self._session(session_token)
        if capability != session.get("transport_capability"):
            raise AuthorityError("transport capability is invalid")
        pending = self._pending.pop(str(permit), None)
        if not isinstance(pending, Mapping) or pending.get("session") != session_token:
            raise AuthorityError("transport permit is missing or replayed")
        if pending.get("authorization_id") != str(session.get("transport_authorization_id") or ""):
            raise AuthorityError("transport canary binding changed")
        if pending.get("authorization_kind") != session.get("transport_authorization_kind"):
            raise AuthorityError("transport authorization domain changed")
        if not isinstance(usage, Mapping) or any(type(usage.get(k)) is not int or usage[k] < 0 for k in ("input_tokens", "output_tokens", "total_tokens")):
            raise AuthorityError("host observed token usage is incomplete")
        receipt = self._signed({"schema": "CODE_MODE_PROVIDER_TRANSPORT_RECEIPT_V1", **dict(pending),
            "provider_response_id": response_id, "token_usage": {k: int(usage[k]) for k in ("input_tokens", "output_tokens", "total_tokens")},
            "finish_reason": finish_reason,
            "authority": "network-transport-boundary-v1"})
        receipt["receipt_hash"] = _hash({k: v for k, v in receipt.items() if k != "receipt_hash"})
        self._transport[session_token].append(receipt)
        return receipt

    def _append_transport_failure_receipt(
        self,
        session_token: str,
        pending: Mapping[str, Any],
        *,
        outcome_state: str,
        settlement_state: str,
        status_code: int | None,
        error_type: str,
        reason_code: str | None = None,
    ) -> dict[str, Any]:
        """Record one host-observed physical failure without inventing usage.

        ``transport_send`` consumes the physical-attempt scalar immediately
        before entering ``urlopen``.  A failure therefore still belongs in
        the issuer-owned transport ledger, even though no successful
        response receipt can be produced.  The identity fields are copied
        from the authenticated pending permit; the only new values describe
        the observed outcome and intentionally leave token usage absent.
        """
        if outcome_state not in {"FAILED_CONFIRMED", "OUTCOME_UNKNOWN"}:
            raise AuthorityError("transport failure outcome state is invalid")
        if settlement_state not in {"SETTLED", "RECONCILING"}:
            raise AuthorityError("transport failure settlement state is invalid")
        if reason_code is None:
            reason_code = (
                f"PROVIDER_HTTP_STATUS_{status_code}"
                if isinstance(status_code, int)
                else "PROVIDER_TRANSPORT_OUTCOME_UNKNOWN"
            )
        if not isinstance(reason_code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,96}", reason_code):
            raise AuthorityError("transport failure reason code is invalid")
        identity = _hash({
            "provider_call_id": pending.get("provider_call_id"),
            "effect_attempt_id": pending.get("effect_attempt_id"),
            "run_id": pending.get("run_id"),
            "attempt": pending.get("attempt"),
            "physical_attempts": pending.get("physical_attempts"),
        })
        body = {
            "schema": "CODE_MODE_PROVIDER_TRANSPORT_FAILURE_RECEIPT_V1",
            **dict(pending),
            "failure_identity": identity,
            "provider_response_id": None,
            "token_usage": None,
            "usage_status": "unknown",
            "usage_settled": False,
            "outcome_state": outcome_state,
            "settlement_state": settlement_state,
            "status_code": status_code,
            "error_type": error_type,
            "reason_code": reason_code,
            "authority": "network-transport-boundary-v1",
        }
        for existing in self._transport.get(session_token, ()):
            if (
                isinstance(existing, Mapping)
                and existing.get("schema") == body["schema"]
                and existing.get("failure_identity") == identity
            ):
                existing_core = {
                    key: value for key, value in existing.items()
                    if key not in {"issuer_id", "issuer_signature", "receipt_hash"}
                }
                if existing_core != body:
                    raise AuthorityError("transport failure identity was reused with different content")
                return dict(existing)
        receipt = self._signed(body)
        receipt["receipt_hash"] = _hash({k: v for k, v in receipt.items() if k != "receipt_hash"})
        self._transport.setdefault(session_token, []).append(receipt)
        return receipt

    def serve(self) -> None:
        reader, writer = self.channel.makefile("rb"), self.channel.makefile("wb")
        for line in reader:
            try:
                request = json.loads(line.decode("utf-8"))
                if not isinstance(request, Mapping):
                    raise AuthorityError("request is not an object")
                response = {"ok": True, "value": self.dispatch(request)}
            except Exception as error:
                status_code = getattr(error, "status_code", None)
                if type(status_code) is not int or not 100 <= status_code <= 599:
                    status_code = None
                reason_code = getattr(error, "reason_code", None)
                if not isinstance(reason_code, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{2,96}", reason_code):
                    reason_code = None
                response = {
                    "ok": False,
                    "error_type": type(error).__name__,
                    "error": str(error)[:240],
                    "error_hash": hashlib.sha256(str(error).encode()).hexdigest(),
                    "status_code": status_code,
                    "reason_code": reason_code,
                }
            writer.write(_canonical(response) + b"\n")
            writer.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-fd", type=int, required=True)
    parser.add_argument("--bootstrap-fd", type=int, required=True)
    args = parser.parse_args(argv)
    if args.control_fd in {0, 1, 2} or args.bootstrap_fd in {0, 1, 2} or args.control_fd == args.bootstrap_fd:
        raise SystemExit(64)
    bootstrap = b""
    while len(bootstrap) < 32:
        chunk = os.read(args.bootstrap_fd, 65536 - len(bootstrap))
        if not chunk:
            break
        bootstrap += chunk
    os.close(args.bootstrap_fd)
    channel = socket.socket(fileno=args.control_fd)
    AuthorityService(channel, bootstrap).serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
