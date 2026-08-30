"""Independent disposable runtime state for Code Mode.

This context intentionally has no dependency on Legacy B+ Genesis, foundation,
activation artifacts, or production authority.  It provides only the Journal,
CAS, ephemeral signing keys, and a run-scoped authority shape needed by the
existing execution chain.  It is not a release or deployment authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from sitina.cas.local import LocalCAS
from sitina.authority.model import AuthorityResolution, AuthorityState
from sitina.journal.local import LocalJournal
from sitina.journal.model import (
    canonical_json_bytes,
    candidate_payload_hash,
    domain_hash,
    parse_canonical_json,
    payload_self_hash,
    execution_parent_hash,
    execution_parent_projection,
    durable_code_mode_authorization_projection,
)
from sitina.orchestrator.code_mode_gate import CodeModeRuntimePolicy
from sitina.security.key_provider import InMemoryKeyProvider, JournalAuthProvider, KeyPurpose
from sitina.storage import SitinaStore
from sitina.runners.provider import (
    ProviderCompletion,
    ProviderProfile,
    ProviderToolCall,
    ProviderToolTurn,
    SUPPORTED_WIRE_PROTOCOLS,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _workspace_observation_hash(root: Path) -> str:
    """Hash a worktree's names, types, symlink targets, and file bytes."""
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root))):
        relative = str(path.relative_to(root))
        try:
            info = path.lstat()
        except OSError as error:
            raise PermissionError("Tester worktree changed while being observed") from error
        if path.is_symlink():
            records.append({"path": relative, "kind": "symlink", "target_hash": hashlib.sha256(os.readlink(path).encode()).hexdigest()})
        elif path.is_dir():
            records.append({"path": relative, "kind": "directory"})
        elif path.is_file():
            records.append({"path": relative, "kind": "file", "size": int(info.st_size), "hash": hashlib.sha256(path.read_bytes()).hexdigest()})
        else:
            raise PermissionError("Tester worktree contains an unsupported special file")
    return hashlib.sha256(canonical_json_bytes(records)).hexdigest()


def _tty_nonce_consumption_command_id(consumption_id: str) -> str:
    """Return the stable Journal command identity for one TTY nonce."""
    if not isinstance(consumption_id, str) or not re.fullmatch(r"[0-9a-f]{64}", consumption_id):
        raise ValueError("TTY nonce consumption identity is invalid")
    # This identity intentionally contains no observed stream version.  The
    # Journal request hash remains submission-specific, so a racing second
    # submit is a command-id conflict rather than an idempotent replay.
    return "code-mode-tty-consume-" + consumption_id


@dataclass(frozen=True)
class CodeModeRuntimeIdentity:
    journal_id: str
    epoch_root: str
    genesis_hash: str
    state_identity: str
    source_root: str = ""
    source_manifest_hash: str = ""


@dataclass(frozen=True)
class CodeModeRuntimeAuthorityHandle:
    """Opaque, process-bound authority for post-execution canary review.

    ``CodeModeRuntimeContext.open`` deliberately does not issue this handle.
    It is created only by the private issuer below and is registered against
    the exact context object and state identity.  A copied mapping, another
    context opened on the same directory, or a self-created Journal/CAS root
    therefore cannot satisfy the canary gate.
    """

    opaque: str
    state_identity: str
    journal_id: str


@dataclass(frozen=True)
class CodeModeExecutionParentBinding:
    """Opaque parent capability for one Code Mode execution run.

    The handle is intentionally not serializable into a model/control input
    that can be replayed: the owning context keeps the canonical record and
    consumes it when deriving a sandbox child capability.
    """

    handle: str
    parent_hash: str
    session_id: str
    run_id: str
    intent_hash: str
    workspace: str
    scope: tuple[str, ...]
    risk_level: str
    attempt: int
    expires_at: int


class CodeModeRuntimeContext:
    """Ephemeral Journal/CAS context used by offline Code Mode execution."""

    def __init__(
        self,
        home: Path,
        provider: InMemoryKeyProvider,
        identity: CodeModeRuntimeIdentity,
        *,
        session_instance_id: str | None = None,
    ):
        self.home = Path(home).expanduser().resolve(strict=True)
        root_stat = os.stat(self.home, follow_symlinks=False)
        self._bound_home = self.home
        self._bound_root_identity = f"{root_stat.st_dev}:{root_stat.st_ino}"
        self.provider = provider
        self.session_instance_id = str(
            session_instance_id or ("session-instance-" + secrets.token_hex(16))
        )
        if not self.session_instance_id.strip():
            raise PermissionError("Code Mode runtime session instance is missing")
        self.identity = identity
        self.source_root = Path(identity.source_root or self.home).expanduser().resolve(strict=True)
        self.source_manifest_hash = identity.source_manifest_hash or identity.genesis_hash
        self.genesis = SimpleNamespace(
            journal_id=identity.journal_id,
            epoch_root=identity.epoch_root,
            genesis_hash=identity.genesis_hash,
        )
        self.authority = SimpleNamespace(
            resolution=AuthorityResolution(
                AuthorityState.JOURNAL_WRITER_AUTHORIZED,
                resolution_id=identity.genesis_hash,
                input_frontier_hash=identity.genesis_hash,
                input_hash=identity.genesis_hash,
                resolver_binary_hash=identity.genesis_hash,
                resolver_profile="code-mode-runtime-v1",
                issued_at=int(time.time()) - 1,
                expires_at=int(time.time()) + 3600,
                reason="ephemeral Code Mode execution state",
            ),
            events=(),
        )
        self._authority_handle: CodeModeRuntimeAuthorityHandle | None = None
        self._broker_client: Any | None = None
        self._broker_session: str | None = None
        self._broker_binding: Mapping[str, Any] | None = None
        self._broker_transport_capability: Any | None = None
        self._broker_transport_ledger: Any | None = None
        self._execution_parents: dict[str, dict[str, Any]] = {}
        self._execution_children: dict[str, dict[str, Any]] = {}
        self._issued_child_attempts: set[tuple[str, str, int]] = set()
        self._invalidated_code_mode_attempts: set[int] = set()
        self._invalidated_code_mode_bindings: set[tuple[str, int]] = set()
        self._revoked_execution_parents: set[str] = set()
        self._canary_authorizations: dict[str, str] = {}
        self._consumed_canary_authorizations: set[str] = set()
        self._request_binding: dict[str, str] | None = None
        # Independent reviewer clients are registered only after an attested
        # reviewer process returns a capability.  A directly opened runtime
        # has no reviewer authority and cannot self-review.
        self._reviewer_sessions: dict[str, Any] = {}
        self._review_request_by_capability: dict[int, dict[str, Any]] = {}
        self._review_request_by_binding: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self._cancelled_review_requests: set[str] = set()
        # Receipt locators are deliberately not kept in a process-local
        # allow-list. Reopenability is proved by the no-replace CAS receipt
        # and its exact same-run Journal fact, so a restarted controller makes
        # the same verification decision.

    @classmethod
    def open(
        cls,
        home: Path,
        *,
        provider: InMemoryKeyProvider | None = None,
        source_root: Path | None = None,
        session_instance_id: str | None = None,
    ) -> "CodeModeRuntimeContext":
        root = Path(home).expanduser().resolve(strict=True)
        marker = root / ".sitina-code-mode-v1"
        marker.touch(exist_ok=True)
        # ToolExecutor's risk/audit primitive uses the normal SitinaStore
        # schema.  Initializing that local state is not a B+ activation: it is
        # the Code Mode state root and contains no Genesis/foundation/PASS.
        SitinaStore(root).init_db()
        source_base = Path(source_root).expanduser().resolve(strict=True) if source_root is not None else root
        source = source_base / "config" / "true_multi_agent_policy.json"
        # Component identity belongs to the source checkout, not the state
        # root.  Include every project config and Python component so a
        # runtime-home copy cannot silently become the executable identity.
        source_paths: list[Path] = []
        config_dir = source_base / "config"
        if config_dir.is_dir():
            source_paths.extend(config_dir.iterdir())
        core_dir = source_base / "core" / "sitina"
        if core_dir.is_dir():
            source_paths.extend(core_dir.rglob("*.py"))
        source_paths = sorted(set(source_paths), key=lambda item: str(item))
        source_records = []
        for path in source_paths:
            relative = str(path.relative_to(source_base))
            if path.is_file() and not path.is_symlink():
                source_records.append({
                    "path": relative,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                })
            else:
                source_records.append({"path": relative, "absent": True})
        source_manifest_hash = hashlib.sha256(canonical_json_bytes(source_records)).hexdigest()
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest() if source.is_file() else "0" * 64
        journal_id = "code-mode-journal-" + hashlib.sha256(str(root).encode()).hexdigest()[:24]
        root_stat = os.stat(root, follow_symlinks=False)
        root_identity = f"{root_stat.st_dev}:{root_stat.st_ino}"
        state_identity = "code-mode-state:" + hashlib.sha256(
            canonical_json_bytes({
                "home": str(root),
                "root_identity": root_identity,
                "journal_id": journal_id,
                "epoch_root": "code-mode-epoch-1",
                "policy_hash": source_hash,
                "source_root": str(source_base),
                "source_manifest_hash": source_manifest_hash,
            })
        ).hexdigest()
        identity = CodeModeRuntimeIdentity(
            journal_id, "code-mode-epoch-1", source_hash, state_identity,
            str(source_base), source_manifest_hash,
        )
        return cls(
            root,
            provider or InMemoryKeyProvider(environment="code-mode", namespace="runtime"),
            identity,
            session_instance_id=session_instance_id,
        )

    def _attach_authority_broker(
        self,
        broker: Any,
        session: str,
        binding: Mapping[str, Any],
        transport_capability: str,
    ) -> None:
        """Attach the only trusted issuer returned by the OS broker client.

        This method is intentionally not an issuer: the broker has already
        created the session and retains the signing key/state.  A context made
        with ``CodeModeRuntimeContext.open`` therefore remains non-authoritative.
        """
        from sitina.orchestrator.code_mode_authority_broker import CodeModeAuthorityBroker
        if not isinstance(broker, CodeModeAuthorityBroker) or not broker.is_attested_host_client():
            raise PermissionError("Code Mode authority must be the concrete host broker")
        if self._broker_client is not None:
            raise PermissionError("Code Mode authority broker is already attached")
        if not isinstance(session, str) or not session or not isinstance(binding, Mapping):
            raise PermissionError("broker runtime binding is invalid")
        if binding.get("runtime_state_identity") != self.identity.state_identity:
            raise PermissionError("broker runtime state identity mismatch")
        if binding.get("runtime_journal_id") != self.identity.journal_id:
            raise PermissionError("broker Journal identity mismatch")
        if binding.get("session_instance_id") != self.session_instance_id:
            raise PermissionError("broker session instance identity mismatch")
        self._broker_client = broker
        self._broker_session = session
        self._broker_binding = dict(binding)
        from sitina.orchestrator.code_mode_authority_broker import BrokerTransportCapability, BrokerTransportLedger
        self._broker_transport_capability = BrokerTransportCapability(broker, session, transport_capability)
        self._broker_transport_ledger = BrokerTransportLedger(broker, session, self._broker_transport_capability)

    def __del__(self) -> None:
        # Test bootstrap fixtures may attach an explicitly owned broker.  The
        # production CLI owns its broker through the factory and closes it at
        # chat exit, so ordinary context collection never tears down a shared
        # session underneath another context.
        broker = getattr(self, "_test_broker", None)
        if broker is not None:
            try:
                broker.close()
            except Exception:
                pass

    @classmethod
    def _make_bootstrap_context_factory(cls, **_kwargs: Any):
        """Retired in-process bootstrap; only the CLI host may connect the external authority host."""
        raise PermissionError(
            "Code Mode trusted contexts require the OS CodeModeAuthorityBroker"
        )

    @property
    def canary_authority_handle(self) -> CodeModeRuntimeAuthorityHandle | None:
        return self._authority_handle

    def canary_authority_binding(self) -> dict[str, str]:
        if self._broker_client is None or self._broker_session is None or not isinstance(self._broker_binding, Mapping):
            raise PermissionError("Code Mode context has no OS-broker authority")
        binding = dict(self._broker_binding)
        current_binding = self._broker_client.read_binding(self._broker_session)
        if current_binding != binding:
            raise PermissionError("Code Mode broker runtime binding changed")
        broker_identity = dict(self._broker_client.identity)
        if (
            binding.get("broker_pid") != broker_identity.get("pid")
            or binding.get("issuer_id") != broker_identity.get("issuer_id")
        ):
            raise PermissionError("Code Mode broker process identity changed")
        try:
            current_stat = os.stat(self._bound_home, follow_symlinks=False)
        except OSError as error:
            raise PermissionError("Code Mode runtime state root is unavailable") from error
        if f"{current_stat.st_dev}:{current_stat.st_ino}" != self._bound_root_identity:
            raise PermissionError("Code Mode runtime state root was replaced")
        return {
            "runtime_state_identity": str(binding["runtime_state_identity"]),
            "runtime_authority_handle_hash": str(binding["runtime_authority_handle_hash"]),
            "runtime_journal_id": str(binding["runtime_journal_id"]),
            "issuer_id": str(broker_identity["issuer_id"]),
            "trust_scope": str(broker_identity.get("trust_scope") or ""),
        }

    def bind_code_mode_request(
        self,
        *,
        session_instance_id: str | None = None,
        session_id: str,
        run_id: str,
        candidate_id: str,
        workspace: Path,
        run_attempt: int,
        generation: str | None = None,
        stream_id: str | None = None,
    ) -> None:
        """Bind this runtime instance to one session/run/candidate request."""

        if isinstance(run_attempt, bool) or not isinstance(run_attempt, int) or run_attempt < 1:
            raise PermissionError("Code Mode request attempt is invalid")
        bound_generation = str(generation or self.identity.epoch_root).strip()
        bound_stream = str(stream_id or f"session/{str(session_id).strip()}").strip()
        binding = {
            "session_instance_id": str(session_instance_id or self.session_instance_id).strip(),
            "session_id": str(session_id).strip(),
            "stream_id": bound_stream,
            "run_id": str(run_id).strip(),
            "run_attempt": run_attempt,
            "generation": bound_generation,
            "candidate_id": str(candidate_id).strip(),
            "workspace": str(Path(workspace).expanduser().resolve(strict=True)),
        }
        if not all(binding.values()) or binding["session_instance_id"] != self.session_instance_id:
            raise PermissionError("Code Mode request binding is incomplete")
        if self._request_binding is not None and self._request_binding != binding:
            previous = dict(self._request_binding)
            if previous.get("run_id") != binding["run_id"]:
                # A conversation may start a second, independent execution
                # run in the same CLI instance.  It starts a fresh attempt
                # namespace; only the run-internal rework path may increment
                # an existing run's attempt.
                new_run_fields = ("session_instance_id", "session_id", "stream_id", "generation", "workspace")
                if (
                    any(previous.get(key) != binding.get(key) for key in new_run_fields)
                    or set(previous) != set(binding)
                    or binding["run_attempt"] != 1
                ):
                    raise PermissionError("Code Mode runtime request binding cannot replace its run namespace")
                self._invalidated_code_mode_bindings.add(
                    (str(previous["run_id"]), int(previous["run_attempt"]))
                )
            else:
                immutable_fields = tuple(key for key in binding if key != "run_attempt")
                if (
                    any(previous.get(key) != binding.get(key) for key in immutable_fields)
                    or set(previous) != set(binding)
                    or binding["run_attempt"] != previous.get("run_attempt", 0) + 1
                ):
                    raise PermissionError("Code Mode runtime request binding cannot be replaced")
                self._invalidated_code_mode_bindings.add(
                    (str(previous["run_id"]), int(previous["run_attempt"]))
                )
                self._invalidated_code_mode_attempts.add(int(previous["run_attempt"]))
        self._request_binding = binding

    def assert_current_code_mode_binding(
        self,
        *,
        session_instance_id: str,
        session_id: str,
        run_id: str,
        run_attempt: int,
        generation: str,
        workspace: Path,
    ) -> None:
        """Require a fact producer to use this runtime's current attempt."""
        current = self._request_binding
        expected = {
            "session_instance_id": str(session_instance_id),
            "session_id": str(session_id),
            "run_id": str(run_id),
            "run_attempt": run_attempt,
            "generation": str(generation),
            "workspace": str(Path(workspace).expanduser().resolve(strict=True)),
        }
        if not isinstance(current, Mapping) or any(current.get(key) != value for key, value in expected.items()):
            raise PermissionError("Code Mode fact is not bound to the current run attempt")

    def latest_execution_attempt(
        self,
        *,
        journal: Any,
        run_id: str,
        session_id: str,
        generation: str,
        workspace: Path,
        require_current: bool = True,
    ) -> dict[str, Any]:
        """Reopen the authenticated attempt chain for the current run.

        The result is derived only from Journal-authenticated events.  It is
        deliberately not a read of an in-memory ``authorization`` field or
        of the last arbitrary payload in the stream.
        """
        self.assert_current_code_mode_binding(
            session_instance_id=self.session_instance_id,
            session_id=session_id, run_id=run_id,
            run_attempt=int((self._request_binding or {}).get("run_attempt") or 0),
            generation=generation, workspace=workspace,
        )
        stream_id = f"run/{run_id}"
        candidates = tuple(
            event for event in journal.iter_events(0)
            if event.stream_id == stream_id
            and isinstance(event.payload, Mapping)
            and (
                event.payload.get("schema") in {
                    "SITINA_EXECUTION_AUTHORIZATION_V1",
                    "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1",
                }
                or event.payload.get("event_type") in {
                    "execution.authorization.bound",
                    "execution.authorization.attempt_advanced",
                }
            )
        )
        if not candidates:
            raise PermissionError("Code Mode execution attempt chain is missing")
        first = candidates[0].payload
        if (
            first.get("schema") != "SITINA_EXECUTION_AUTHORIZATION_V1"
            or first.get("event_type") != "execution.authorization.bound"
            or first.get("run_attempt") != 1
        ):
            raise PermissionError("Code Mode attempt chain has no attempt-one root")
        identity_fields = ("session_instance_id", "session_id", "run_id", "generation", "workspace")
        for field, expected in (
            ("session_instance_id", self.session_instance_id), ("session_id", session_id),
            ("run_id", run_id), ("generation", generation),
            ("workspace", str(Path(workspace).expanduser().resolve(strict=True))),
        ):
            if first.get(field) != expected:
                raise PermissionError("Code Mode attempt root binding changed")
        if not isinstance(first.get("authorization_ref"), str) or not first["authorization_ref"]:
            raise PermissionError("Code Mode attempt-one authorization is missing")
        latest = dict(first)
        first_receipt_ref = first.get("authorization_object_ref")
        if (
            not isinstance(first_receipt_ref, str)
            or first_receipt_ref not in tuple(getattr(candidates[0], "object_refs", ()))
        ):
            raise PermissionError("Code Mode attempt-one authorization receipt is not event-owned")
        latest_attempt = 1
        for event in candidates[1:]:
            value = dict(event.payload)
            if (
                value.get("schema") != "SITINA_EXECUTION_ATTEMPT_ADVANCED_V1"
                or value.get("event_type") != "execution.authorization.attempt_advanced"
            ):
                raise PermissionError("Code Mode attempt transition schema is not exact")
            if value.get("previous_run_attempt") != latest_attempt or value.get("run_attempt") != latest_attempt + 1:
                raise PermissionError("Code Mode attempt chain is not contiguous")
            for field in identity_fields:
                if value.get(field) != latest.get(field):
                    raise PermissionError("Code Mode attempt chain identity changed")
            if value.get("previous_authorization_ref") != latest.get("authorization_ref"):
                raise PermissionError("Code Mode attempt predecessor is not exact")
            if value.get("authorization_ref") in {
                latest.get("authorization_ref"), value.get("previous_authorization_ref")
            }:
                raise PermissionError("Code Mode attempt authorization was reused")
            receipt_ref = value.get("authorization_receipt_ref")
            receipt_hash = value.get("authorization_receipt_hash")
            if not isinstance(receipt_ref, str) or not receipt_ref or not isinstance(receipt_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", receipt_hash):
                raise PermissionError("Code Mode attempt authorization receipt is incomplete")
            if receipt_ref not in tuple(getattr(event, "object_refs", ())):
                raise PermissionError("Code Mode attempt authorization receipt is not event-owned")
            nested = value.get("code_mode_authorization")
            if not isinstance(nested, Mapping) or nested.get("run_attempt") != value.get("run_attempt") or nested.get("authorization_ref") != value.get("authorization_ref"):
                raise PermissionError("Code Mode attempt authorization projection is not exact")
            if "authorization_token" in nested:
                raise PermissionError("Code Mode attempt authorization contains a bearer token")
            try:
                durable_nested = durable_code_mode_authorization_projection(nested)
            except Exception as error:
                raise PermissionError("Code Mode attempt authorization token commitment is invalid") from error
            if dict(nested) != durable_nested:
                raise PermissionError("Code Mode attempt authorization is not a durable projection")
            replan = value.get("replan_plan")
            if (
                not isinstance(replan, Mapping)
                or set(replan) != {"approach", "acceptance_checks"}
                or not isinstance(replan.get("approach"), str)
                or not replan["approach"].strip()
                or type(replan.get("acceptance_checks")) is not list
                or not replan["acceptance_checks"]
                or any(not isinstance(item, str) or not item.strip() for item in replan["acceptance_checks"])
            ):
                raise PermissionError("Code Mode replan commitment is missing")
            expected_replan_hash = hashlib.sha256(canonical_json_bytes(dict(replan))).hexdigest()
            if value.get("replan_plan_hash") != expected_replan_hash:
                raise PermissionError("Code Mode replan content hash is not exact")
            if value.get("plan_hash") != value.get("replan_plan_hash"):
                raise PermissionError("Code Mode attempt plan is not the committed replan")
            if any(not isinstance(value.get(field), str) or not value[field] for field in (
                "prior_plan_hash", "prior_failure_type", "prior_failure_hash"
            )):
                raise PermissionError("Code Mode replan predecessor commitment is incomplete")
            latest = value
            latest_attempt += 1
        current_attempt = self._request_binding.get("run_attempt") if isinstance(self._request_binding, Mapping) else None
        if require_current and current_attempt != latest_attempt:
            raise PermissionError("Code Mode current attempt differs from Journal latest attempt")
        return latest

    def _authoritative_transport_ledger(self) -> tuple[Any, object]:
        """Return the issuer-bound physical transport ledger and capability."""
        self.canary_authority_binding()
        if self._broker_transport_ledger is None or self._broker_transport_capability is None:
            raise PermissionError("Code Mode broker transport ledger is unavailable")
        return self._broker_transport_ledger, self._broker_transport_capability

    def authoritative_provider_profile(self, profile_name: str | None = None) -> ProviderProfile:
        """Resolve provider identity from the host without exposing a token."""
        if self._broker_client is None or self._broker_session is None:
            raise PermissionError("authoritative provider profile requires the Code Mode host")
        selected = str(profile_name or "").strip()
        if not selected:
            try:
                policy = json.loads((self.source_root / "config" / "true_multi_agent_policy.json").read_text(encoding="utf-8"))
                selected = str(policy.get("provider_profile") or "").strip()
            except (OSError, json.JSONDecodeError):
                selected = ""
        if not selected:
            raise PermissionError("authoritative provider profile is not configured")
        value = self._broker_client.read_provider_profile(selected)
        if set(value) != {
            "name", "base_url", "model", "wire_protocol",
            "adapter_capabilities", "allowed_endpoint_hosts",
        }:
            raise PermissionError("host provider profile summary shape is invalid")
        name = value.get("name")
        base_url = value.get("base_url")
        model = value.get("model")
        protocol = value.get("wire_protocol")
        raw_caps = value.get("adapter_capabilities")
        raw_hosts = value.get("allowed_endpoint_hosts")
        if (
            type(name) is not str or not name
            or type(base_url) is not str or not base_url
            or type(model) is not str or not model
            or type(protocol) is not str or protocol not in SUPPORTED_WIRE_PROTOCOLS
            or type(raw_caps) is not list
            or any(type(item) is not str or not item for item in raw_caps)
            or type(raw_hosts) is not list
            or any(type(item) is not str or not item for item in raw_hosts)
        ):
            raise PermissionError("host provider profile summary is incomplete")
        return ProviderProfile(
            name,
            base_url,
            "",
            model,
            protocol,
            tuple(raw_caps),
            tuple(raw_hosts),
        )

    def request_acceptance_transaction(
        self,
        *,
        locators: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Obtain the host-signed acceptance envelope from locators only.

        Direct/offline contexts intentionally have no authority signer.  The
        only signing path is the already-attested broker connection, and the
        host derives the issuer key and payload commitment itself.
        """
        if self._broker_client is None or self._broker_session is None or not isinstance(self._broker_binding, Mapping):
            raise PermissionError("Code Mode authority signing requires the attested host")
        if not isinstance(locators, Mapping) or locators.get("schema") != "CODE_MODE_ACCEPTANCE_LOCATOR_REQUEST_V2":
            raise PermissionError("Code Mode acceptance requires durable locators")
        body = dict(locators)
        body["runtime_authority_handle_hash"] = str(
            self._broker_binding.get("runtime_authority_handle_hash") or ""
        )
        return self._broker_client.request_acceptance_transaction(self._broker_session, body)

    def request_completion_plan(self, plan_inputs: Mapping[str, Any]) -> dict[str, Any]:
        """Ask the attested host to construct a plan from bound locators."""
        if self._broker_client is None or self._broker_session is None or not isinstance(plan_inputs, Mapping):
            raise PermissionError("Code Mode completion plan signing requires the attested host")
        value = dict(plan_inputs)
        if value.get("schema") != "CODE_MODE_COMPLETION_LOCATOR_REQUEST_V2":
            raise PermissionError("completion plan requires durable locators")
        value["runtime_authority_handle_hash"] = str(
            self._broker_binding.get("runtime_authority_handle_hash") if isinstance(self._broker_binding, Mapping) else ""
        )
        return self._broker_client.request_completion_plan(self._broker_session, value)

    def issue_pre_provider_authorization(
        self, *, session_id: str, turn_index: int, run_id: str,
        run_attempt: int, generation: str, provider_profile: str, provider_model: str,
    ) -> dict[str, Any]:
        """Exchange the current controller scope for routine Provider use.

        This is intentionally separate from ``issue_canary_authorization``.
        It returns only the host-issued permit to the live controller and is
        never copied into controls, Journal/CAS facts, prompts, or workers.
        The broker/host derives the fixed phase allowlist and authenticates
        the controller handle against its attested session key.
        """
        if self._broker_client is None or self._broker_session is None:
            raise PermissionError("pre-provider authorization requires the OS CodeModeAuthorityBroker")
        if not isinstance(session_id, str) or not session_id or type(turn_index) is not int or turn_index < 0:
            raise PermissionError("pre-provider conversation binding is invalid")
        if not isinstance(run_id, str) or not run_id or type(run_attempt) is not int or run_attempt != 1:
            raise PermissionError("pre-provider run binding is invalid")
        if not isinstance(provider_profile, str) or not provider_profile or not isinstance(provider_model, str) or not provider_model:
            raise PermissionError("pre-provider provider binding is invalid")
        self.canary_authority_binding()
        return self._broker_client.issue_pre_provider_authorization(
            self._broker_session,
            session_instance_id=self.session_instance_id,
            conversation_session_id=session_id,
            turn_index=turn_index,
            run_id=run_id,
            run_attempt=run_attempt,
            generation=generation,
            provider_profile=provider_profile,
            provider_model=provider_model,
        )

    def issue_canary_authorization(
        self, locator_request: Mapping[str, Any], *, live_capability: Any | None = None,
    ) -> dict[str, Any]:
        """Ask the broker to sign a permit using a one-use controller handle."""
        self.canary_authority_binding()
        if self._broker_client is None or self._broker_session is None:
            raise PermissionError("Code Mode canary issuer is unavailable")
        if not isinstance(locator_request, Mapping) or locator_request.get("schema") != "CODE_MODE_CANARY_LOCATOR_REQUEST_V2":
            raise PermissionError("Code Mode canary issuer requires typed durable locators")
        try:
            from sitina.orchestrator.true_multi_agent_runtime import LiveNetworkCapabilityHandle
            if not isinstance(live_capability, LiveNetworkCapabilityHandle):
                raise PermissionError("Code Mode canary issuance requires a controller-owned live handle")
            capability_ref = self._broker_client.register_live_capability(
                self._broker_session, live_capability,
            )
            if not capability_ref:
                raise PermissionError("live capability registration returned no identity")
            value = dict(locator_request)
            value["live_capability_ref"] = capability_ref
            authorization = self._broker_client.issue_bound_canary(self._broker_session, value)
            live_capability.consume()
            return authorization
        except PermissionError:
            raise
        except Exception as error:
            raise PermissionError("Code Mode live capability could not be admitted") from error

    def register_canary_authorization(self, authorization: Mapping[str, Any]) -> None:
        """Register the exact authorization issued for this runtime state."""
        if self._broker_client is not None and self._broker_session is not None:
            if not self._broker_client.validate_bound_canary(self._broker_session, authorization):
                raise PermissionError("canary authorization was not issued by this broker")
            run_attempt_value = authorization.get("run_attempt")
            if isinstance(run_attempt_value, bool) or not isinstance(run_attempt_value, int) or run_attempt_value < 1:
                raise PermissionError("canary authorization has no issued run attempt")
            self.bind_code_mode_request(
                session_instance_id=self.session_instance_id,
                session_id=str(authorization.get("session_id") or ""),
                run_id=str(authorization.get("run_id") or ""),
                candidate_id=str(authorization.get("candidate_id") or ""),
                workspace=Path(str(authorization.get("workspace") or "")),
                run_attempt=int(run_attempt_value),
                generation=str(authorization.get("generation") or self.identity.epoch_root),
                stream_id=str(authorization.get("stream_id") or "") or None,
            )
            if self._broker_transport_ledger is None:
                raise PermissionError("canary transport ledger is unavailable")
            self._broker_transport_ledger.bind_canary_authorization(authorization)
            return
        raise PermissionError("canary registration requires the OS CodeModeAuthorityBroker")

    def validate_canary_authorization(self, authorization: Mapping[str, Any]) -> bool:
        if self._broker_client is None or self._broker_session is None:
            return False
        return self._broker_client.validate_bound_canary(self._broker_session, authorization)

    def consume_canary_authorization(self, authorization: Mapping[str, Any]) -> None:
        if not self.validate_canary_authorization(authorization):
            raise PermissionError("canary authorization is invalid, expired, or already consumed")
        if self._broker_client is None or self._broker_session is None:
            raise PermissionError("canary consumption requires the OS CodeModeAuthorityBroker")
        self._broker_client.consume_bound_canary(self._broker_session, authorization)

    def open_runtime_writer(self) -> LocalJournal:
        self._assert_bound_root()
        # The writer's Code Mode parent/child path must be able to reopen the
        # authenticated parent object, not merely trust a copied Journal
        # proof.  Keep this verifier read-only: it never exposes CAS keys or
        # plaintext to workers, and the parent object itself contains only the
        # non-secret token commitment.
        cas = LocalCAS.open(self._bound_home, self.provider, namespace_kind="code_mode")
        journal = LocalJournal.open(
            self._bound_home,
            JournalAuthProvider(self.provider),
            journal_id=self.identity.journal_id,
            epoch=1,
            namespace_kind="code_mode",
            cas=cas,
        )
        # The runtime provider is only the Journal event authenticator.  A
        # Code Mode authority operation is accepted only after this writer is
        # pinned to the attested host's public Ed25519 identity.
        broker_identity = dict(getattr(self._broker_client, "identity", {})) if self._broker_client is not None else {}
        key_id = broker_identity.get("authority_key_id")
        public_hex = broker_identity.get("authority_public_key_hex")
        if isinstance(key_id, str) and isinstance(public_hex, str):
            try:
                journal._install_external_authority_pin(key_id, bytes.fromhex(public_hex))
            except (ValueError, TypeError) as error:
                journal.close()
                raise PermissionError("attested authority public key is invalid") from error
        return journal

    def open_cas(self) -> LocalCAS:
        self._assert_bound_root()
        return LocalCAS.open(self._bound_home, self.provider, namespace_kind="code_mode")

    def _assert_bound_root(self) -> None:
        try:
            current_stat = os.stat(self._bound_home, follow_symlinks=False)
        except OSError as error:
            raise PermissionError("Code Mode runtime state root is unavailable") from error
        if f"{current_stat.st_dev}:{current_stat.st_ino}" != self._bound_root_identity:
            raise PermissionError("Code Mode runtime state root was replaced")

    def _verify_host_signature(self, key_id: object, message: bytes, signature: bytes) -> bool:
        identity = dict(getattr(self._broker_client, "identity", {})) if self._broker_client is not None else {}
        if key_id != identity.get("authority_key_id"):
            return False
        public_hex = identity.get("authority_public_key_hex")
        try:
            if not isinstance(public_hex, str) or hashlib.sha256(bytes.fromhex(public_hex)).hexdigest() != str(key_id).removeprefix("host-ed25519:"):
                return False
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(signature, message)
            return True
        except Exception:
            return False

    def open_runtime_state_reader(self) -> LocalJournal:
        return self.open_runtime_writer()

    def open_cas_reader(self) -> LocalCAS:
        return self.open_cas()

    def _publish_offline_evidence_receipt(
        self,
        body: Mapping[str, Any],
        *,
        reviewer_proof: Mapping[str, Any] | None = None,
        reviewer_session: Any | None = None,
        tty_confirmation: Any | None = None,
    ) -> dict[str, Any]:
        """Publish a refs-only, re-openable offline evidence receipt.

        Offline evidence is never a canary credential.  It is nevertheless
        durable and content addressed so the acceptance layer can verify the
        exact command/result again instead of trusting a caller's status map.
        Raw stdout, secrets, and model text are intentionally not accepted.
        """
        self._assert_bound_root()
        value = dict(body)
        if "raw_output" in value or "raw_text" in value:
            raise PermissionError("offline evidence receipts may not contain raw output")
        if value.get("schema") == "CODE_MODE_EVIDENCE_PACKAGE_V1":
            raise PermissionError(
                "a Tester cannot seal an evidence package; only the Code Mode execution sealer may publish one"
            )
        value.setdefault("runtime_state_identity", self.identity.state_identity)
        value.setdefault("runtime_journal_id", self.identity.journal_id)
        # Test evidence is produced by this runtime's controlled test path.
        # Reviewer evidence is the sole exception: its issuer and signature
        # must come from the independent reviewer process and are never
        # accepted as caller-supplied identity fields.
        if tty_confirmation is not None:
            from sitina.orchestrator.code_mode_reviewer import TTYReviewConfirmation
            if not isinstance(tty_confirmation, TTYReviewConfirmation):
                raise PermissionError("TTY receipt requires the controller-owned confirmation")
            if reviewer_proof is not None or reviewer_session is None:
                raise PermissionError("TTY receipt cannot use headless reviewer proof")
            if value.get("schema") != "CODE_MODE_REVIEW_RECEIPT_V2":
                raise PermissionError("TTY confirmation is bound to Review V2")
            value["authority_class"] = "TTY_REVIEW_AUTHORITY"
            value["issuer_identity"] = "code-mode-tty-authority"
        elif reviewer_proof is None:
            if value.get("issuer_identity", "code-mode-offline-runtime-v1") != "code-mode-offline-runtime-v1":
                raise PermissionError("offline evidence issuer identity is not the Code Mode sealer")
            if value.get("authority_class", "OFFLINE_NON_AUTHORITATIVE") != "OFFLINE_NON_AUTHORITATIVE":
                raise PermissionError("offline evidence cannot claim authoritative status")
            value["issuer_identity"] = "code-mode-offline-runtime-v1"
            value["authority_class"] = "OFFLINE_NON_AUTHORITATIVE"
        else:
            proof = dict(reviewer_proof)
            from sitina.orchestrator.code_mode_reviewer import CodeModeReviewerSession
            if not isinstance(reviewer_session, CodeModeReviewerSession) or not reviewer_session.is_attested_reviewer():
                raise PermissionError("reviewer proof requires the attested reviewer session")
            if not reviewer_session.verify_receipt(proof):
                raise PermissionError("reviewer proof is not issued by the attested reviewer session")
            if value.get("schema") != "CODE_MODE_REVIEW_RECEIPT_V2":
                raise PermissionError("reviewer proof is bound to the wrong receipt schema")
            for field in (
                "issuer_id", "issuer_signature", "review_binding_hash", "reviewer_id", "decision",
                "producer_issuer_id", "producer_public_key", "producer_signature",
            ):
                if not isinstance(proof.get(field), str) or not proof[field]:
                    raise PermissionError("reviewer proof is incomplete")
            if proof.get("authority_class") != "INDEPENDENT_REVIEWER_AUTHORITY":
                raise PermissionError("reviewer proof is not independently issued")
            if proof.get("decision") not in {"ACCEPT", "REJECT"}:
                raise PermissionError("reviewer authority returned an invalid decision")
            # The proof is copied only after the attested reviewer client has
            # verified it.  No caller decision/reviewer_id is accepted here.
            value.update(proof)
            value["issuer_identity"] = proof["issuer_id"]
            value["authority_class"] = "INDEPENDENT_REVIEWER_AUTHORITY"
        value.setdefault("issued_at", int(time.time()))
        expiry = int(value.get("expires_at") or 0)
        if expiry <= int(value["issued_at"]) or expiry > int(value["issued_at"]) + 900:
            raise PermissionError("offline evidence receipt expiry is invalid")
        value["content_hash"] = hashlib.sha256(canonical_json_bytes(value)).hexdigest()
        cas = self.open_cas()
        publication = cas.publish_plaintext(
            canonical_json_bytes(value),
            tenant_id="code-mode-evidence",
            purpose_class="code-mode-evidence",
            media_type="application/json",
        )
        receipt = publication.receipt
        reference_id = receipt.object_ref.reference_id
        run_id = str(value.get("run_id") or f"offline-{self.identity.journal_id}")
        # The CAS locator alone is not an evidence producer.  Record a typed
        # fact in the same runtime Journal after publication so the acceptance
        # layer can require both durable objects and an authenticated
        # same-run producer event.
        try:
            from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream
            purpose_by_schema = {
                "CODE_MODE_MACHINE_CHECK_RECEIPT_V1": "code-mode-machine-check",
                "CODE_MODE_EVIDENCE_PACKAGE_V1": "code-mode-execution-package",
                "CODE_MODE_EXECUTION_EVIDENCE_CORE_V1": "code-mode-execution-evidence-core",
                "CODE_MODE_REVIEW_REQUEST_V2": "code-mode-review-request",
                "CODE_MODE_REVIEW_RECEIPT_V2": "code-mode-evidence",
            }
            journal = self.open_runtime_writer()
            try:
                stream = CanonicalStream(journal, run_id, f"run/{run_id}", self.identity.genesis_hash)
                _fact_receipt, fact_events = stream.append_code_mode_fact(
                    "evidence-receipt",
                    ({
                        "schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
                        "evidence_schema": value["schema"],
                        "purpose_class": purpose_by_schema.get(value["schema"], "code-mode-evidence"),
                        "reference_id": reference_id,
                        "content_hash": value["content_hash"],
                        "candidate_id": value.get("candidate_id"),
                        "tree_hash": value.get("tree_hash"),
                        "run_id": run_id,
                        "authorization_ref": value.get("authorization_ref"),
                        "issuer_identity": value.get("issuer_identity"),
                        "authority_class": value.get("authority_class"),
                        "session_id": value.get("session_id"),
                        "session_instance_id": value.get("session_instance_id"),
                        "run_attempt": value.get("run_attempt"),
                        "turn_index": value.get("turn_index"),
                        "generation": value.get("generation"),
                        "verifier_identity": value.get("verifier_identity"),
                        "worktree_digest": value.get("worktree_after_hash"),
                        "diff_hash": value.get("diff_hash"),
                        # A machine check or Review request is not the run's
                        # closing root.  That root is emitted only by the
                        # controller after all execution/cleanup receipts.
                        "closing_root": value.get("closing_root") is True,
                        "_object_refs": [reference_id],
                    },),
                    actor=str(value.get("issuer_identity") or "code-mode-runtime"),
                    proofs=(publication.receipt,),
                )
            finally:
                journal.close()
        except Exception as error:
            raise PermissionError("offline evidence Journal fact could not be recorded") from error
        return {
            "schema": value["schema"],
            "reference_id": reference_id,
            "content_hash": value["content_hash"],
            "receipt_hash": value["content_hash"],
            "object_hash": receipt.object_ref.object_id,
            "payload_hash": value["content_hash"],
            "plaintext_commitment": receipt.object_ref.plaintext_commitment,
            "run_id": str(value.get("run_id") or ""),
            "runtime_state_identity": self.identity.state_identity,
            "runtime_journal_id": self.identity.journal_id,
            "issuer_identity": value["issuer_identity"],
            "journal_event_hash": str(fact_events[0]["event_hash"]) if fact_events else "",
            # These are locator binding hints, never trusted facts.  The
            # reopener obtains the authoritative values from the CAS body and
            # same-run Journal fact, but the host RPC needs the typed scope to
            # reject a locator before opening an unrelated object.
            **{
                key: value[key]
                for key in (
                    "session_instance_id", "session_id", "turn_index", "run_attempt",
                    "generation", "candidate_id", "tree_hash", "verifier_identity",
                    "authorization_ref",
                )
                if key in value
            },
            **({"review_request_ref": str(value["review_request_ref"])} if value.get("review_request_ref") else {}),
            "fresh_verified": bool(receipt.fresh_verified),
            "no_replace_published": bool(receipt.no_replace_published),
        }

    def seal_execution_evidence_package(
        self,
        *,
        package: Mapping[str, Any],
        run_id: str,
        closing_root_event_hash: str,
        journal: Any | None = None,
        cas: Any | None = None,
        run_stream: Any | None = None,
    ) -> dict[str, Any]:
        """Publish the controller-owned full execution package.

        This is intentionally separate from ``_publish_offline_evidence_receipt``:
        a Tester receipt must never be able to claim the full execution-package
        schema.  The caller is the already-running Controller path; this method
        still reopens the current Journal and requires the exact pre-package
        closing fact before publishing a no-replace CAS object and its typed
        same-run fact.
        """
        self._assert_bound_root()
        if not isinstance(package, Mapping) or package.get("schema") != "CODE_MODE_EVIDENCE_PACKAGE_V1":
            raise PermissionError("execution sealer requires the Code Mode evidence package schema")
        if not isinstance(run_id, str) or not run_id or package.get("run_id") != run_id:
            raise PermissionError("execution package run binding is invalid")
        if not isinstance(closing_root_event_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", closing_root_event_hash):
            raise PermissionError("execution package closing root hash is invalid")
        if package.get("closing_root_event_hash") != closing_root_event_hash:
            raise PermissionError("execution package closing root binding is inconsistent")
        if any(key in package for key in ("raw_output", "raw_text", "provider_secret", "api_key")):
            raise PermissionError("execution package contains forbidden raw content")
        body = {key: value for key, value in package.items() if key != "content_hash"}
        expected_hash = hashlib.sha256(canonical_json_bytes(body)).hexdigest()
        if package.get("content_hash") != expected_hash:
            raise PermissionError("execution package content hash is invalid")
        owned_journal = journal is None
        journal = journal or self.open_runtime_state_reader()
        try:
            roots = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and str(getattr(event, "event_hash", "")) == closing_root_event_hash
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("schema") == "CODE_MODE_EVIDENCE_CLOSING_ROOT_V1"
                and event.payload.get("run_id") == run_id
            ]
        finally:
            if owned_journal:
                journal.close()
        if len(roots) != 1:
            raise PermissionError("execution package has no exact same-run closing fact")
        cas = cas or self.open_cas()
        publication = cas.publish_plaintext(
            canonical_json_bytes(dict(package)),
            tenant_id="code-mode-evidence",
            purpose_class="code-mode-execution-package",
            media_type="application/json",
        )
        receipt = publication.receipt
        reference_id = receipt.object_ref.reference_id
        if not receipt.fresh_verified or not receipt.no_replace_published:
            raise PermissionError("execution package CAS publication was not immutable")
        owned_journal = journal is None
        journal = journal or self.open_runtime_writer()
        try:
            from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream
            stream = run_stream or CanonicalStream(journal, run_id, f"run/{run_id}", self.identity.genesis_hash)
            _fact, fact_events = stream.append_code_mode_fact(
                "evidence-package",
                ({
                    "schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
                    "evidence_schema": "CODE_MODE_EVIDENCE_PACKAGE_V1",
                    "purpose_class": "code-mode-execution-package",
                    "reference_id": reference_id,
                    "content_hash": package["content_hash"],
                    "candidate_id": package.get("candidate_id"),
                    "tree_hash": package.get("tree_hash"),
                    "run_id": run_id,
                    "issuer_identity": "code-mode-receipt-sealer",
                    "authority_class": "CODE_MODE_EXECUTION_SEALER",
                    "session_id": package.get("session_id"),
                    "session_instance_id": package.get("session_instance_id"),
                    "run_attempt": package.get("run_attempt"),
                    "turn_index": package.get("turn_index"),
                    "generation": package.get("generation"),
                    "authorization_ref": package.get("authorization_ref"),
                    "verifier_identity": package.get("verifier_identity"),
                    "worktree_digest": package.get("worktree_after_hash"),
                    "diff_hash": package.get("diff_hash"),
                    "closing_root": True,
                    "closing_root_event_hash": closing_root_event_hash,
                    "_object_refs": [reference_id],
                },),
                actor="code-mode-receipt-sealer",
                proofs=(receipt,),
            )
        finally:
            if owned_journal:
                journal.close()
        if len(fact_events) != 1:
            raise PermissionError("execution package Journal fact was not unique")
        return {
            "schema": "CODE_MODE_EVIDENCE_PACKAGE_V1",
            "reference_id": reference_id,
            "content_hash": package["content_hash"],
            "receipt_hash": package["content_hash"],
            "object_hash": receipt.object_ref.object_id,
            "payload_hash": package["content_hash"],
            "plaintext_commitment": receipt.object_ref.plaintext_commitment,
            "run_id": run_id,
            **{
                key: package[key]
                for key in (
                    "session_instance_id", "session_id", "turn_index", "run_attempt",
                    "generation", "candidate_id", "tree_hash", "verifier_identity",
                    "authorization_ref", "provider_profile", "provider_model",
                )
                if key in package
            },
            "journal_event_hash": fact_events[0]["event_hash"],
            "fresh_verified": True,
            "no_replace_published": True,
        }

    def create_execution_review_request(
        self,
        *,
        candidate: Mapping[str, Any],
        machine_check: Mapping[str, Any],
        evidence_package: Mapping[str, Any],
        journal: Any,
        cas: Any,
        run_stream: Any,
    ) -> dict[str, Any]:
        """Create a Review V2 request on the open controller stream.

        This controller-only variant exists because terminalization already
        owns the Journal writer.  It consumes only the two freshly sealed CAS
        locators, reopens both objects through that writer's CAS, and appends
        the request fact before the final Code Mode receipt root.
        """
        if not isinstance(candidate, Mapping) or not isinstance(machine_check, Mapping) or not isinstance(evidence_package, Mapping):
            raise PermissionError("execution Review V2 requires controller locators")
        machine_ref = machine_check.get("reference_id")
        machine_hash = machine_check.get("content_hash")
        package_ref = evidence_package.get("reference_id")
        package_hash = evidence_package.get("content_hash")
        if not all(isinstance(value, str) and value.startswith("cas:") for value in (machine_ref, package_ref)):
            raise PermissionError("execution Review V2 locator is invalid")
        if not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in (machine_hash, package_hash)):
            raise PermissionError("execution Review V2 locator hash is invalid")
        machine_body = parse_canonical_json(cas.open_verified(cas.resolve_reference(machine_ref)))
        package_body = parse_canonical_json(cas.open_verified(cas.resolve_reference(package_ref)))
        for reference in (machine_ref, package_ref):
            proof = cas.verify_existing(cas.resolve_reference(reference))
            if not proof.fresh_verified or not proof.no_replace_published:
                raise PermissionError("execution Review V2 locator is not fresh and no-replace")
        if not isinstance(machine_body, Mapping) or machine_body.get("schema") != "CODE_MODE_MACHINE_CHECK_RECEIPT_V1":
            raise PermissionError("execution Review V2 machine receipt is invalid")
        if not isinstance(package_body, Mapping) or package_body.get("schema") != "CODE_MODE_EVIDENCE_PACKAGE_V1":
            raise PermissionError("execution Review V2 package is invalid")
        if (
            machine_body.get("content_hash") != machine_hash
            or package_body.get("content_hash") != package_hash
            or package_body.get("machine_check_ref") != machine_ref
            or package_body.get("machine_check_hash") != machine_hash
            or package_body.get("candidate_id") != candidate.get("candidate_id")
            or package_body.get("tree_hash") != candidate.get("tree_hash")
            or machine_body.get("candidate_id") != candidate.get("candidate_id")
            or machine_body.get("tree_hash") != candidate.get("tree_hash")
        ):
            raise PermissionError("execution Review V2 package binding is invalid")
        for field in ("run_id", "session_id", "generation", "verifier_identity"):
            if field not in package_body or package_body.get(field) != machine_body.get(field):
                raise PermissionError("execution Review V2 identity binding is incomplete")
        run_id = str(package_body.get("run_id") or "")
        closing_hash = str(package_body.get("closing_root_event_hash") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", closing_hash):
            raise PermissionError("execution Review V2 closing root binding is incomplete")
        events = tuple(event for event in journal.iter_events(0) if event.stream_id == f"run/{run_id}")
        if not any(str(getattr(event, "event_hash", "")) == closing_hash for event in events):
            raise PermissionError("execution Review V2 closing fact is not in the current run")
        request = dict(package_body)
        request.pop("content_hash", None)
        request.update({
            "schema": "CODE_MODE_REVIEW_REQUEST_V2",
            "machine_check_ref": machine_ref,
            "machine_check_hash": machine_hash,
            "evidence_package_ref": package_ref,
            "evidence_package_hash": package_hash,
            "tty_nonce": secrets.token_urlsafe(24),
            "tty_expires_at": min(int(time.time()) + 120, int(package_body.get("expires_at") or int(time.time()) + 120)),
        })
        request["content_hash"] = hashlib.sha256(canonical_json_bytes(request)).hexdigest()
        publication = cas.publish_plaintext(
            canonical_json_bytes(request), tenant_id="code-mode-evidence",
            purpose_class="code-mode-review-request", media_type="application/json",
        )
        receipt = publication.receipt
        from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream
        stream = run_stream or CanonicalStream(journal, run_id, f"run/{run_id}", self.identity.genesis_hash)
        _receipt, fact_events = stream.append_code_mode_fact(
            "review-request",
            ({
                "schema": "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1",
                "evidence_schema": "CODE_MODE_REVIEW_REQUEST_V2",
                "reference_id": receipt.object_ref.reference_id,
                "content_hash": request["content_hash"],
                "purpose_class": "code-mode-review-request",
                "candidate_id": request.get("candidate_id"), "tree_hash": request.get("tree_hash"),
                "run_id": run_id, "session_id": request.get("session_id"),
                "session_instance_id": request.get("session_instance_id"),
                "run_attempt": request.get("run_attempt"),
                "turn_index": request.get("turn_index"),
                "generation": request.get("generation"), "verifier_identity": request.get("verifier_identity"),
                "closing_root": False, "_object_refs": [receipt.object_ref.reference_id],
            },), actor="code-mode-receipt-sealer", proofs=(receipt,)
        )
        if len(fact_events) != 1:
            raise PermissionError("execution Review V2 request fact was not unique")
        return {
            "schema": "CODE_MODE_REVIEW_REQUEST_V2",
            "reference_id": receipt.object_ref.reference_id,
            "content_hash": request["content_hash"],
            "receipt_hash": request["content_hash"],
            "object_hash": receipt.object_ref.object_id,
            "payload_hash": request["content_hash"],
            "plaintext_commitment": receipt.object_ref.plaintext_commitment,
            "run_id": run_id,
            "journal_event_hash": fact_events[0]["event_hash"],
            "fresh_verified": True, "no_replace_published": True,
        }

    def _consume_tty_nonce(
        self,
        *,
        request: Mapping[str, Any],
        confirmation: Any,
    ) -> dict[str, Any]:
        """Consume the durable Review V2 nonce before issuing a TTY receipt."""
        from sitina.orchestrator.code_mode_reviewer import TTYReviewConfirmation
        if not isinstance(confirmation, TTYReviewConfirmation):
            raise PermissionError("TTY confirmation is not controller-owned")
        request_ref = str(request.get("reference_id") or "")
        request_hash = str(request.get("content_hash") or "")
        nonce = getattr(confirmation, "_nonce", "")
        if (
            getattr(confirmation, "_session", None) is None
            or not request_ref.startswith("cas:")
            or not re.fullmatch(r"cas:[0-9a-f]{64}", request_ref)
            or not re.fullmatch(r"[0-9a-f]{64}", request_hash)
            or not isinstance(nonce, str) or not nonce
            or getattr(confirmation, "_request_key", None) != (request_ref, request_hash)
            or getattr(confirmation, "_expires_at", 0) <= int(time.time())
        ):
            raise PermissionError("TTY confirmation is not bound to the current request")
        nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        run_id = str(request.get("run_id") or "")
        if not run_id:
            raise PermissionError("TTY request has no run binding")
        journal = self.open_runtime_state_reader()
        try:
            events = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and isinstance(getattr(event, "payload", None), Mapping)
            ]
        finally:
            journal.close()
        if any(
            event.payload.get("schema") == "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1"
            and event.payload.get("nonce_hash") == nonce_hash
            and isinstance(event.payload.get("consumption_id"), str)
            for event in events
        ):
            raise PermissionError("TTY review nonce was already consumed")
        if any(
            event.payload.get("schema") == "CODE_MODE_REVIEW_CANCELLED_V1"
            and event.payload.get("reference_id") == request_ref
            and event.payload.get("content_hash") == request_hash
            for event in events
        ):
            raise PermissionError("TTY review request was cancelled")

        consumption = {
            "schema": "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1",
            "event_type": "code-mode.tty-review-nonce-consumed",
            "request_ref": request_ref,
            "request_hash": request_hash,
            "candidate_id": request.get("candidate_id"),
            "tree_hash": request.get("tree_hash"),
            "run_id": run_id,
            "session_instance_id": request.get("session_instance_id"),
            "run_attempt": request.get("run_attempt"),
            "session_id": request.get("session_id"),
            "turn_index": request.get("turn_index"),
            "generation": request.get("generation"),
            "nonce_hash": nonce_hash,
            "consumed": True,
            # The CAS identity is derived only from the exact request/nonce
            # binding.  Concurrent consumers therefore address one
            # no-replace object; Journal compare-and-append decides which
            # caller wins the stream version race.
            "consumption_id": hashlib.sha256(canonical_json_bytes({
                "request_ref": request_ref, "request_hash": request_hash,
                "candidate_id": request.get("candidate_id"),
                "tree_hash": request.get("tree_hash"), "run_id": run_id,
                "session_id": request.get("session_id"), "generation": request.get("generation"),
                "session_instance_id": request.get("session_instance_id"),
                "run_attempt": request.get("run_attempt"),
                "turn_index": request.get("turn_index"),
                "nonce_hash": nonce_hash,
            })).hexdigest(),
            "authority_class": "TTY_REVIEW_AUTHORITY",
        }
        consumption_hash = hashlib.sha256(canonical_json_bytes(consumption)).hexdigest()
        consumption["content_hash"] = consumption_hash
        cas = self.open_cas()
        publication = cas.publish_plaintext(
            canonical_json_bytes(consumption), tenant_id="code-mode-evidence",
            purpose_class="code-mode-tty-nonce-consumption", media_type="application/json",
        )
        receipt = publication.receipt
        from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream
        journal = self.open_runtime_writer()
        try:
            stream = CanonicalStream(journal, run_id, f"run/{run_id}", self.identity.genesis_hash)
            _receipt, committed = stream.append_tty_nonce_consumption(
                {**consumption, "reference_id": receipt.object_ref.reference_id,
                 "_object_refs": [receipt.object_ref.reference_id]},
                actor="code-mode-tty-authority", proofs=(receipt,),
                # The command identity is the nonce's immutable consumption
                # identity and deliberately excludes the stream version.  A
                # fresh request nonce makes a racing second submission a
                # LocalJournal command-id conflict even when it observes the
                # same pre-consumption head.
                command_id=_tty_nonce_consumption_command_id(str(consumption["consumption_id"])),
                request_nonce=secrets.token_hex(16),
            )
        finally:
            journal.close()
        if not committed:
            raise PermissionError("TTY nonce consumption was not durably committed")
        journal = self.open_runtime_state_reader()
        try:
            committed_nonce_events = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("schema") == "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1"
                and event.payload.get("nonce_hash") == nonce_hash
                and event.payload.get("consumption_id") == consumption["consumption_id"]
            ]
        finally:
            journal.close()
        if len(committed_nonce_events) != 1:
            raise PermissionError("TTY nonce consumption is not unique after commit")
        return {
            "reference_id": receipt.object_ref.reference_id,
            "content_hash": consumption_hash,
            "journal_event_hash": str(committed[0]["event_hash"]),
            "nonce_hash": nonce_hash,
            "consumption_id": str(consumption["consumption_id"]),
        }

    def _verify_tty_review_receipt(self, receipt: Mapping[str, Any]) -> bool:
        """Re-open and verify the controller-owned TTY nonce consumption."""
        if not isinstance(receipt, Mapping) or receipt.get("authority_class") != "TTY_REVIEW_AUTHORITY":
            return False
        if receipt.get("issuer_identity") != "code-mode-tty-authority" or receipt.get("decision") != "ACCEPT":
            return False
        if (
            not isinstance(receipt.get("tty_issuer_id"), str)
            or not receipt.get("tty_issuer_id")
            or receipt.get("reviewer_session_id") != receipt.get("tty_issuer_id")
        ):
            return False
        nonce_ref = receipt.get("tty_consumption_ref")
        nonce_hash = receipt.get("tty_nonce_hash")
        consumption_id = receipt.get("tty_consumption_id")
        event_hash = receipt.get("tty_consumption_event_hash")
        if (
            not isinstance(nonce_ref, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", nonce_ref)
            or not isinstance(nonce_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce_hash)
            or not isinstance(consumption_id, str) or not re.fullmatch(r"[0-9a-f]{64}", consumption_id)
            or not isinstance(event_hash, str) or not event_hash
        ):
            return False
        try:
            cas = self.open_cas_reader()
            proof = cas.verify_existing(cas.resolve_reference(nonce_ref))
            if not proof.fresh_verified or not proof.no_replace_published:
                return False
            consumption = parse_canonical_json(cas.open_verified(cas.resolve_reference(nonce_ref)))
            body = {key: value for key, value in consumption.items() if key != "content_hash"}
            if consumption.get("content_hash") != hashlib.sha256(canonical_json_bytes(body)).hexdigest():
                return False
            if (
                consumption.get("nonce_hash") != nonce_hash
                or consumption.get("consumption_id") != consumption_id
                or consumption.get("consumed") is not True
                or consumption.get("content_hash") != receipt.get("tty_consumption_hash")
                or consumption.get("authority_class") != "TTY_REVIEW_AUTHORITY"
                or consumption.get("session_id") != receipt.get("session_id")
                or consumption.get("request_ref") != receipt.get("review_request_ref")
                or consumption.get("request_hash") != receipt.get("review_request_hash")
                or consumption.get("generation") != receipt.get("generation")
            ):
                return False
            run_id = str(receipt.get("run_id") or "")
            journal = self.open_runtime_state_reader()
            try:
                nonce_events = [
                    event for event in journal.iter_events(0)
                    if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                    and isinstance(getattr(event, "payload", None), Mapping)
                    and event.payload.get("schema") == "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1"
                    and event.payload.get("nonce_hash") == nonce_hash
                ]
                consumption_events = [
                    event for event in nonce_events
                    if event.payload.get("consumption_id") == consumption_id
                ]
                matches = [
                    event for event in journal.iter_events(0)
                    if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                    and str(getattr(event, "event_hash", "")) == event_hash
                    and isinstance(getattr(event, "payload", None), Mapping)
                    and event.payload.get("schema") == "CODE_MODE_TTY_REVIEW_NONCE_CONSUMED_V1"
                    and event.payload.get("reference_id") == nonce_ref
                    and event.payload.get("nonce_hash") == nonce_hash
                    and event.payload.get("consumption_id") == consumption_id
                    and event.payload.get("run_id") == run_id
                    and event.payload.get("candidate_id") == receipt.get("candidate_id")
                    and event.payload.get("tree_hash") == receipt.get("tree_hash")
                ]
            finally:
                journal.close()
            # Reopen the complete same-run nonce set, not merely a matching
            # projection.  A valid receipt has exactly one consumption for the
            # nonce and exactly one event for its immutable consumption ID;
            # foreign/repeated nonce events cannot be hidden by selecting the
            # receipt's ID first.
            if len(nonce_events) != 1 or len(consumption_events) != 1 or len(matches) != 1:
                return False
            request = self._reopen_offline_review_request(
                candidate={"candidate_id": receipt.get("candidate_id"), "tree_hash": receipt.get("tree_hash")},
                request={"schema": "CODE_MODE_REVIEW_REQUEST_V2",
                         "reference_id": receipt.get("review_request_ref"),
                         "content_hash": receipt.get("review_request_hash")},
            )
            return all(receipt.get(field) == request.get(field) for field in (
                "candidate_id", "tree_hash", "run_id", "session_id", "generation",
                "verifier_identity", "machine_check_hash", "evidence_package_hash",
                "source_manifest_hash", "worktree_before_hash", "worktree_after_hash", "diff_hash",
            ))
        except Exception:
            return False

    def register_reviewer_session(self, reviewer_session: Any) -> None:
        """Register one attested reviewer client for CAS receipt reopening."""
        from sitina.orchestrator.code_mode_reviewer import CodeModeReviewerSession
        if not isinstance(reviewer_session, CodeModeReviewerSession) or not reviewer_session.is_attested_reviewer():
            raise PermissionError("reviewer authority is not an attested independent session")
        issuer_id = str(getattr(reviewer_session, "identity", {}).get("issuer_id") or "")
        if not issuer_id or issuer_id == "code-mode-offline-runtime-v1":
            raise PermissionError("reviewer issuer is not independent from the test producer")
        current = self._reviewer_sessions.get(issuer_id)
        if current is not None and current is not reviewer_session:
            raise PermissionError("reviewer issuer is already bound to another session")
        self._reviewer_sessions[issuer_id] = reviewer_session

    def _verify_offline_reviewer_receipt(self, receipt: Mapping[str, Any]) -> bool:
        issuer_id = str(receipt.get("issuer_id") or "")
        session = self._reviewer_sessions.get(issuer_id)
        return bool(session is not None and session.verify_receipt(receipt))

    def seal_offline_test_receipt(
        self,
        *,
        candidate: Mapping[str, Any],
        command: list[str] | tuple[str, ...],
        test_inventory: list[str] | tuple[str, ...],
        interpreter: str,
        dependencies: Mapping[str, Any],
        cwd: Path,
        return_code: int,
        test_ids: list[str] | tuple[str, ...],
        output_summary: Mapping[str, Any],
        failures: int = 0,
        errors: int = 0,
        skipped: int = 0,
        unexpected_successes: int = 0,
        expires_at: int | None = None,
    ) -> dict[str, Any]:
        raise PermissionError(
            "caller-supplied test results cannot create a machine check; use the controlled Tester execution path"
        )

    def run_controlled_tester(
        self,
        *,
        candidate: Mapping[str, Any],
        command: list[str] | tuple[str, ...],
        test_inventory: list[str] | tuple[str, ...],
        interpreter: str,
        dependencies: Mapping[str, Any],
        cwd: Path,
        timeout: float = 120.0,
        controller_session: Any | None = None,
    ) -> dict[str, Any]:
        """Run the controller-owned Tester and seal only its observation.

        No return code, test status, or findings are accepted from the caller.
        The subprocess boundary produces the observation; the runtime records
        only hash-only output and derives MACHINE_CHECK_READY from an observed
        non-help test command whose targets are present and match the declared
        inventory. This is deliberately offline and not a canary authority.
        """
        from sitina.orchestrator.code_mode_controller import CodeModeControllerSession
        if not isinstance(controller_session, CodeModeControllerSession) or controller_session.context is not self:
            raise PermissionError("controlled Tester requires the active Code Mode controller session")
        controller_session.assert_live()
        if not isinstance(candidate, Mapping) or not candidate.get("candidate_id") or not candidate.get("tree_hash"):
            raise ValueError("offline test receipt requires a candidate identity")
        if not isinstance(command, (list, tuple)) or not command or not all(isinstance(item, str) and item for item in command):
            raise ValueError("offline test receipt requires an exact command")
        if not isinstance(test_inventory, (list, tuple)) or not test_inventory:
            raise ValueError("offline test receipt requires a complete test inventory")
        workdir = Path(cwd).expanduser().resolve(strict=True)
        if workdir != controller_session.workspace:
            raise PermissionError("controlled Tester cwd is outside the controller workspace")
        # The run identity is controller-owned.  There is deliberately no
        # caller-provided override: a model, tool, or ordinary helper cannot
        # choose which run receives the Tester evidence.
        effective_run_id = str(controller_session.run_id)
        command_value = list(command)
        inventory_value = list(test_inventory)
        preflight_reason: str | None = None
        # A successful process is not automatically a successful test.  The
        # controller must be able to identify real unittest targets in the
        # selected worktree and the declared inventory must be exactly the
        # targets in the command.  Help-only and target-less invocations are
        # observations of the CLI, not Tester evidence.
        if any(item in {"-h", "--help"} for item in command_value):
            preflight_reason = "help-only Tester command has no test target"
        elif str(command_value[0]).startswith("/") and str(Path(command_value[0]).expanduser().resolve(strict=False)) != str(Path(interpreter).expanduser().resolve(strict=False)):
            preflight_reason = "Tester interpreter does not match the executable in the command"
        elif "-m" not in command_value:
            preflight_reason = "Tester command is not a structured module invocation"
        else:
            module_at = command_value.index("-m")
            if module_at + 1 >= len(command_value) or command_value[module_at + 1] != "unittest":
                preflight_reason = "Tester command is not python -m unittest"
            else:
                targets = [
                    item for item in command_value[module_at + 2:]
                    if item not in {"-v", "--verbose", "-q", "--quiet", "--locals"}
                    and not item.startswith("-")
                ]
                if not targets:
                    preflight_reason = "unittest invocation has no test target"
                elif targets != inventory_value:
                    preflight_reason = "Tester command targets do not match test inventory"
                else:
                    for target in targets:
                        module_name = target.replace("::", ".").split(".", 1)[0] if "::" in target else target
                        target_base = workdir / module_name.replace(".", "/")
                        target_path = target_base.with_suffix(".py")
                        if not target_path.is_file() and not target_base.is_dir():
                            preflight_reason = "declared Tester target is not present in the worktree"
                            break
        before_worktree_hash = _workspace_observation_hash(workdir)
        if preflight_reason is None:
            completed = subprocess.run(
                command_value, cwd=str(workdir), capture_output=True, timeout=float(timeout), check=False,
                env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"},
            )
            observed_output = completed.stdout + completed.stderr
            observed_return_code = int(completed.returncode)
            test_ids_value = inventory_value
            observed_failures = 0 if observed_return_code == 0 else 1
            executed = True
        else:
            observed_output = preflight_reason.encode("utf-8")
            observed_return_code = 2
            test_ids_value = []
            observed_failures = 1
            executed = False
        output_summary = {
            "sha256": hashlib.sha256(observed_output).hexdigest(),
            "size": len(observed_output),
        }
        after_worktree_hash = _workspace_observation_hash(workdir)
        workspace_observation_after_hash = _workspace_observation_hash(workdir)
        diff_hash = hashlib.sha256(canonical_json_bytes({
            "before": before_worktree_hash, "after": after_worktree_hash,
        })).hexdigest()
        verifier_path = Path(__file__).with_name("code_mode_gate.py")
        verifier_identity = hashlib.sha256(verifier_path.read_bytes()).hexdigest()
        issued_at = int(time.time())
        dependency_hash = hashlib.sha256(canonical_json_bytes(dict(dependencies))).hexdigest()
        generation = str(
            controller_session.authorization.get("generation")
            or getattr(self, "current_generation", "")
            or self.identity.epoch_root
        )
        if not generation:
            raise PermissionError("Tester evidence requires the current authority generation")
        current_binding_assertion = getattr(self, "assert_current_code_mode_binding", None)
        if callable(current_binding_assertion):
            current_binding_assertion(
                session_instance_id=str(controller_session.session_instance_id),
                session_id=str(controller_session.session_id),
                run_id=effective_run_id,
                run_attempt=int(controller_session.run_attempt),
                generation=generation,
                workspace=workdir,
            )
        if candidate.get("generation") is not None and str(candidate.get("generation")) != generation:
            raise PermissionError("Tester evidence generation does not match the current candidate")
        body = {
            "schema": "CODE_MODE_MACHINE_CHECK_RECEIPT_V1",
            "status": "MACHINE_CHECK_READY" if observed_return_code == 0 and executed else "MACHINE_CHECK_FAILED",
            "candidate_id": str(candidate["candidate_id"]),
            "tree_hash": str(candidate["tree_hash"]),
            "source_manifest_hash": str(candidate.get("source_manifest_hash") or ""),
            "candidate_worktree_digest": str(candidate.get("worktree_digest") or ""),
            "command": command_value,
            "command_hash": hashlib.sha256(canonical_json_bytes(command_value)).hexdigest(),
            "test_inventory": inventory_value,
            "inventory_hash": hashlib.sha256(canonical_json_bytes(inventory_value)).hexdigest(),
            "interpreter": str(interpreter),
            # Dependency values are never evidence.  Persist only the
            # controller-computed identity; the complete lock remains in the
            # runtime's private execution context.
            "dependencies": {"identity_hash": dependency_hash},
            "dependencies_hash": dependency_hash,
            "cwd": str(workdir),
            "return_code": observed_return_code,
            "test_ids": test_ids_value,
            "failures": observed_failures, "errors": 0, "skipped": 0,
            "unexpected_successes": 0,
            "output_summary": {"sha256": str(output_summary["sha256"]), "size": int(output_summary["size"])},
            "run_id": effective_run_id,
            "session_instance_id": str(controller_session.session_instance_id),
            "run_attempt": int(getattr(controller_session, "run_attempt", 0) or 0),
            "session_id": str(controller_session.session_id),
            "generation": generation,
            "verifier_identity": verifier_identity,
            "worktree_before_hash": before_worktree_hash,
            "worktree_after_hash": after_worktree_hash,
            "workspace_observation_after_hash": workspace_observation_after_hash,
            "diff_hash": diff_hash,
            "issued_at": issued_at,
            "expires_at": issued_at + 900,
            "execution_observed": executed,
            "preflight_failure": preflight_reason,
        }
        machine_receipt = self._publish_offline_evidence_receipt(body)
        # Return the locator plus a hash-bound, non-authoritative projection
        # useful to the caller for display.  Reopeners never trust this
        # projection; they load the CAS object and Journal fact again.
        return machine_receipt | {
            "status": body["status"],
            "execution_observed": bool(body["execution_observed"]),
            "preflight_failure": body["preflight_failure"],
            "candidate_id": body["candidate_id"],
            "tree_hash": body["tree_hash"],
            "generation": body["generation"],
        }

    def _reopen_bound_test_receipt(self, *, candidate: Mapping[str, Any], test_receipt: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(test_receipt, Mapping) or not isinstance(test_receipt.get("content_hash"), str):
            raise ValueError("offline reviewer receipt requires a test receipt binding")
        reference_id = test_receipt.get("reference_id")
        run_id = str(test_receipt.get("run_id") or f"offline-{self.identity.journal_id}")
        if not isinstance(reference_id, str) or not reference_id.startswith("cas:"):
            raise PermissionError("reviewer requires a durable test receipt reference")
        try:
            cas = self.open_cas_reader()
            object_ref = cas.resolve_reference(reference_id)
            if test_receipt.get("object_hash") != object_ref.object_id:
                raise PermissionError("bound test receipt object identity is inconsistent")
            proof = cas.verify_existing(object_ref)
            if not proof.fresh_verified or not proof.no_replace_published:
                raise PermissionError("bound test receipt CAS proof is not fresh and no-replace")
            body = parse_canonical_json(cas.open_verified(object_ref))
        except Exception as error:
            raise PermissionError("bound test receipt could not be reopened") from error
        if (
            not isinstance(body, Mapping)
            or body.get("schema") != "CODE_MODE_MACHINE_CHECK_RECEIPT_V1"
            or body.get("content_hash") != test_receipt.get("content_hash")
            or test_receipt.get("receipt_hash") != test_receipt.get("content_hash")
            or body.get("run_id") != run_id
            or not isinstance(body.get("session_instance_id"), str)
            or not body.get("session_instance_id")
            or type(body.get("run_attempt")) is not int
            or body.get("run_attempt") < 1
            or body.get("candidate_id") != candidate.get("candidate_id")
            or body.get("tree_hash") != candidate.get("tree_hash")
            or body.get("content_hash") != hashlib.sha256(canonical_json_bytes({
                key: item for key, item in body.items() if key != "content_hash"
            })).hexdigest()
        ):
            raise PermissionError("bound test receipt content does not match reviewer binding")
        try:
            journal = self.open_runtime_state_reader()
            try:
                facts = [
                    event for event in journal.iter_events(0)
                    if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                    and isinstance(getattr(event, "payload", None), Mapping)
                    and event.payload.get("schema") == "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1"
                    and event.payload.get("evidence_schema") == "CODE_MODE_MACHINE_CHECK_RECEIPT_V1"
                    and event.payload.get("reference_id") == reference_id
                    and event.payload.get("content_hash") == body.get("content_hash")
                    and event.payload.get("candidate_id") == body.get("candidate_id")
                    and event.payload.get("tree_hash") == body.get("tree_hash")
                    and event.payload.get("run_id") == run_id
                ]
            finally:
                journal.close()
        except Exception as error:
            raise PermissionError("bound test receipt Journal fact could not be reopened") from error
        if len(facts) != 1 or str(test_receipt.get("journal_event_hash") or "") != facts[0].event_hash:
            raise PermissionError("bound test receipt lacks its exact same-run Journal fact")
        reopened = dict(body)
        reopened["reference_id"] = reference_id
        reopened["object_hash"] = object_ref.object_id
        reopened["payload_hash"] = str(body.get("content_hash"))
        reopened["plaintext_commitment"] = proof.object_ref.plaintext_commitment
        return reopened

    def _reopen_bound_evidence_package(
        self,
        *,
        candidate: Mapping[str, Any],
        machine: Mapping[str, Any],
        evidence_package_ref: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Reopen a distinct, controller-produced full evidence package.

        A locator is only an address.  The package is accepted here only when
        its no-replace CAS object, machine receipt link, and all execution
        identity fields agree with the current controller observation.
        """
        reference_id = evidence_package_ref.get("reference_id")
        content_hash = evidence_package_ref.get("content_hash")
        if (
            not isinstance(reference_id, str)
            or not isinstance(content_hash, str)
            or reference_id == str(machine.get("reference_id") or "")
            or content_hash == str(machine.get("content_hash") or "")
        ):
            raise PermissionError("evidence package must be a distinct durable locator")
        try:
            cas = self.open_cas_reader()
            object_ref = cas.resolve_reference(reference_id)
            if evidence_package_ref.get("object_hash") != object_ref.object_id:
                raise PermissionError("evidence package object identity is inconsistent")
            proof = cas.verify_existing(object_ref)
            if not proof.fresh_verified or not proof.no_replace_published:
                raise PermissionError("evidence package CAS proof is not fresh and no-replace")
            body = parse_canonical_json(cas.open_verified(object_ref))
        except Exception as error:
            raise PermissionError("evidence package could not be reopened") from error
        if (
            not isinstance(body, Mapping)
            or body.get("schema") != "CODE_MODE_EVIDENCE_PACKAGE_V1"
            or body.get("content_hash") != content_hash
            or body.get("content_hash") != payload_self_hash(body)
            or body.get("machine_check_ref") != machine.get("reference_id")
            or body.get("machine_check_hash") != machine.get("content_hash")
            or body.get("candidate_id") != candidate.get("candidate_id")
            or body.get("tree_hash") != candidate.get("tree_hash")
            or body.get("session_id") != machine.get("session_id")
            or body.get("session_instance_id") != machine.get("session_instance_id")
            or body.get("run_attempt") != machine.get("run_attempt")
            or body.get("run_id") != machine.get("run_id")
            or body.get("generation") != machine.get("generation")
            or body.get("verifier_identity") != machine.get("verifier_identity")
        ):
            raise PermissionError("evidence package binding does not match the machine observation")
        # The machine receipt and the package are two views of the same
        # controller observation, not independently self-consistent records.
        # Cross-check every identity that can affect the review decision before
        # accepting the package locator.
        for field in (
            "source_manifest_hash", "worktree_before_hash", "worktree_after_hash",
            "diff_hash", "worktree_delta_hash", "generation", "verifier_identity",
            "candidate_manifest_ref", "candidate_manifest_hash", "candidate_worktree_digest",
            "baseline_authorization_identity",
        ):
            if body.get(field) != machine.get(field):
                raise PermissionError("evidence package and machine receipt diverge: " + field)
        candidate_ref = body.get("candidate_manifest_ref")
        candidate_hash = body.get("candidate_manifest_hash")
        if (
            not isinstance(candidate_ref, str)
            or not isinstance(candidate_hash, str)
            or not candidate_ref.startswith("cas:")
            or not re.fullmatch(r"[0-9a-f]{64}", candidate_hash)
            or candidate_ref != machine.get("candidate_manifest_ref")
            or candidate_hash != machine.get("candidate_manifest_hash")
        ):
            raise PermissionError("evidence package candidate manifest locator is incomplete")
        candidate_body = self.reopen_candidate_manifest(
            {
                "reference_id": candidate_ref,
                "content_hash": candidate_hash,
                "run_id": body.get("run_id"),
                "candidate_id": body.get("candidate_id"),
                "tree_hash": body.get("tree_hash"),
            },
            run_id=str(body.get("run_id") or ""),
        )
        for field in ("candidate_id", "tree_hash", "source_manifest_hash", "worktree_digest", "generation"):
            expected = body.get(field)
            if field == "worktree_digest":
                expected = body.get("candidate_worktree_digest")
            if expected is not None and candidate_body.get(field) != expected:
                raise PermissionError("evidence package candidate manifest diverges: " + field)
        # A full package is an execution-sealer product, not a projection of
        # a Tester result.  These references must point at independently
        # recorded same-run observations; empty/constant ledgers are not
        # evidence.
        required = (
            "worktree_before_hash", "worktree_after_hash", "diff_hash",
            "source_manifest_hash", "execution_receipt_refs", "tool_ledger",
            "tester", "cleanup", "closing_root", "closing_root_event_hash",
            "candidate_manifest_ref", "candidate_manifest_hash",
            "baseline_authorization_identity",
        )
        if any(field not in body for field in required):
            raise PermissionError("evidence package is missing required execution evidence")
        refs = body.get("execution_receipt_refs")
        if not isinstance(refs, Mapping) or not refs or any(
            not isinstance(key, str) or not isinstance(value, str) or not value.startswith("cas:")
            for key, value in refs.items()
        ):
            raise PermissionError("evidence package has no execution receipt lineage")
        tester = body.get("tester")
        if (
            not isinstance(tester, Mapping)
            or tester.get("receipt_ref") != machine.get("reference_id")
            or tester.get("receipt_hash") != machine.get("content_hash")
            or tester.get("status") != machine.get("status")
        ):
            raise PermissionError("evidence package Tester link is invalid")
        cleanup = body.get("cleanup")
        closing_root = body.get("closing_root")
        if (
            not isinstance(cleanup, Mapping) or cleanup.get("observed") is not True
            or not isinstance(closing_root, Mapping) or closing_root.get("sealed") is not True
            or not isinstance(body.get("closing_root_event_hash"), str)
            or not body.get("closing_root_event_hash")
        ):
            raise PermissionError("evidence package cleanup or closing-root evidence is invalid")
        try:
            journal = self.open_runtime_state_reader()
            try:
                package_facts = [
                    event for event in journal.iter_events(0)
                    if str(getattr(event, "stream_id", "")) == f"run/{machine.get('run_id')}"
                    and isinstance(getattr(event, "payload", None), Mapping)
                    and event.payload.get("schema") == "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1"
                    and event.payload.get("evidence_schema") == "CODE_MODE_EVIDENCE_PACKAGE_V1"
                    and event.payload.get("reference_id") == reference_id
                    and event.payload.get("content_hash") == content_hash
                    and event.payload.get("run_id") == machine.get("run_id")
                    and event.payload.get("closing_root") is True
                ]
            finally:
                journal.close()
        except Exception as error:
            raise PermissionError("evidence package Journal lineage could not be reopened") from error
        if len(package_facts) != 1:
            raise PermissionError("evidence package has no exact same-run closing fact")
        closing_hash = str(body.get("closing_root_event_hash") or "")
        refs = dict(body.get("execution_receipt_refs") or {})
        try:
            cas = self.open_cas_reader()
            journal = self.open_runtime_state_reader()
            try:
                run_events = [
                    event for event in journal.iter_events(0)
                    if str(getattr(event, "stream_id", "")) == f"run/{machine.get('run_id')}"
                    and isinstance(getattr(event, "payload", None), Mapping)
                    and event.payload.get("run_id", machine.get("run_id")) == machine.get("run_id")
                ]
                if not any(str(getattr(event, "event_hash", "")) == closing_hash for event in run_events):
                    raise PermissionError("evidence package closing root is not in the current run stream")
                for purpose, receipt_ref in refs.items():
                    object_ref = cas.resolve_reference(receipt_ref)
                    proof = cas.verify_existing(object_ref)
                    if not proof.fresh_verified or not proof.no_replace_published:
                        raise PermissionError("execution receipt CAS proof is not fresh and no-replace")
                    linked = [
                        event for event in run_events
                        if receipt_ref in set(event.payload.get("_object_refs") or ())
                        or event.payload.get("receipt_ref") == receipt_ref
                        or event.payload.get("reference_id") == receipt_ref
                    ]
                    if not linked:
                        raise PermissionError("execution receipt is not linked from the current run Journal")
            finally:
                journal.close()
        except PermissionError:
            raise
        except Exception as error:
            raise PermissionError("execution receipt lineage could not be reopened") from error
        # The CAS body is deliberately locator-free.  Only this verified
        # in-memory projection may carry the exact source locator onward to
        # the TTY authority; callers cannot replace it with an arbitrary
        # request key.
        reopened = dict(body)
        reopened["reference_id"] = reference_id
        reopened["content_hash"] = content_hash
        reopened["object_hash"] = object_ref.object_id
        reopened["payload_hash"] = content_hash
        reopened["plaintext_commitment"] = proof.object_ref.plaintext_commitment
        return reopened

    def _reopen_offline_review_request(
        self, *, candidate: Mapping[str, Any], request: Mapping[str, Any],
        accepted_at: int | None = None,
    ) -> dict[str, Any]:
        """Reopen the exact controller-created Review V2 request."""
        if not isinstance(request, Mapping) or request.get("schema") != "CODE_MODE_REVIEW_REQUEST_V2":
            raise PermissionError("review request schema is invalid")
        reference_id = request.get("reference_id")
        content_hash = request.get("content_hash")
        if not isinstance(reference_id, str) or not isinstance(content_hash, str):
            raise PermissionError("review request locator is incomplete")
        try:
            cas = self.open_cas_reader()
            object_ref = cas.resolve_reference(reference_id)
            proof = cas.verify_existing(object_ref)
            if not proof.fresh_verified or not proof.no_replace_published:
                raise PermissionError("review request CAS proof is not fresh and no-replace")
            body = parse_canonical_json(cas.open_verified(object_ref))
        except Exception as error:
            raise PermissionError("review request could not be reopened") from error
        if (
            not isinstance(body, Mapping)
            or body.get("schema") != "CODE_MODE_REVIEW_REQUEST_V2"
            or body.get("content_hash") != content_hash
            or body.get("content_hash") != hashlib.sha256(canonical_json_bytes({k: v for k, v in body.items() if k != "content_hash"})).hexdigest()
            or body.get("candidate_id") != candidate.get("candidate_id")
            or body.get("tree_hash") != candidate.get("tree_hash")
            or body.get("machine_check_ref") == body.get("evidence_package_ref")
            or body.get("machine_check_hash") == body.get("evidence_package_hash")
        ):
            raise PermissionError("review request content or binding is invalid")
        try:
            machine_ref = str(body["machine_check_ref"])
            machine_object = cas.resolve_reference(machine_ref)
            machine_proof = cas.verify_existing(machine_object)
            if not machine_proof.fresh_verified or not machine_proof.no_replace_published:
                raise PermissionError("review request machine receipt CAS proof is not fresh and no-replace")
            machine_body = parse_canonical_json(cas.open_verified(machine_object))
        except Exception as error:
            raise PermissionError("review request machine receipt could not be reopened") from error
        if (
            not isinstance(machine_body, Mapping)
            or machine_body.get("schema") != "CODE_MODE_MACHINE_CHECK_RECEIPT_V1"
            or machine_body.get("content_hash") != body.get("machine_check_hash")
            or machine_body.get("candidate_id") != body.get("candidate_id")
            or machine_body.get("tree_hash") != body.get("tree_hash")
            or machine_body.get("run_id") != body.get("run_id")
            or machine_body.get("session_id") != body.get("session_id")
            or not isinstance(machine_body.get("session_instance_id"), str)
            or not machine_body.get("session_instance_id")
            or type(machine_body.get("run_attempt")) is not int
            or machine_body.get("run_attempt") < 1
            or machine_body.get("session_instance_id") != body.get("session_instance_id")
            or machine_body.get("run_attempt") != body.get("run_attempt")
        ):
            raise PermissionError("review request machine receipt binding is invalid")
        try:
            package_ref = str(body["evidence_package_ref"])
            package_object = cas.resolve_reference(package_ref)
            package_proof = cas.verify_existing(package_object)
            if not package_proof.fresh_verified or not package_proof.no_replace_published:
                raise PermissionError("review request evidence package CAS proof is not fresh and no-replace")
            package_body = parse_canonical_json(cas.open_verified(package_object))
        except Exception as error:
            raise PermissionError("review request evidence package could not be reopened") from error
        if (
            not isinstance(package_body, Mapping)
            or package_body.get("schema") != "CODE_MODE_EVIDENCE_PACKAGE_V1"
            or package_body.get("content_hash") != body.get("evidence_package_hash")
            or package_body.get("content_hash") != payload_self_hash(package_body)
            or package_body.get("machine_check_ref") != body.get("machine_check_ref")
            or package_body.get("machine_check_hash") != body.get("machine_check_hash")
            or package_body.get("candidate_id") != body.get("candidate_id")
            or package_body.get("tree_hash") != body.get("tree_hash")
            or package_body.get("run_id") != body.get("run_id")
            or package_body.get("session_id") != body.get("session_id")
            or package_body.get("session_instance_id") != body.get("session_instance_id")
            or package_body.get("run_attempt") != body.get("run_attempt")
            or package_body.get("generation") != body.get("generation")
            or package_body.get("verifier_identity") != body.get("verifier_identity")
        ):
            raise PermissionError("review request evidence package binding is invalid")
        for field in (
            "source_manifest_hash", "worktree_before_hash", "worktree_after_hash",
            "diff_hash", "worktree_delta_hash", "generation", "verifier_identity",
            "candidate_manifest_ref", "candidate_manifest_hash", "candidate_worktree_digest",
            "baseline_authorization_identity",
        ):
            if package_body.get(field) != machine_body.get(field):
                raise PermissionError("review request machine/package binding diverges: " + field)
        for field in ("worktree_before_hash", "worktree_after_hash", "diff_hash", "tool_ledger", "tester", "cleanup", "closing_root"):
            if field not in package_body:
                raise PermissionError("review request evidence package is incomplete")
        try:
            journal = self.open_runtime_state_reader()
            try:
                request_facts = [
                    event.payload for event in journal.iter_events(0)
                    if str(getattr(event, "stream_id", "")) == f"run/{body.get('run_id')}"
                    and isinstance(getattr(event, "payload", None), Mapping)
                    and event.payload.get("schema") == "CODE_MODE_EVIDENCE_RECEIPT_FACT_V1"
                    and event.payload.get("evidence_schema") == "CODE_MODE_REVIEW_REQUEST_V2"
                    and event.payload.get("reference_id") == reference_id
                    and event.payload.get("content_hash") == content_hash
                    and event.payload.get("candidate_id") == body.get("candidate_id")
                    and event.payload.get("tree_hash") == body.get("tree_hash")
                    and event.payload.get("run_id") == body.get("run_id")
                ]
            finally:
                journal.close()
        except Exception as error:
            raise PermissionError("review request Journal fact could not be reopened") from error
        if len(request_facts) != 1:
            raise PermissionError("review request has no unique same-run Journal fact")
        try:
            journal = self.open_runtime_state_reader()
            try:
                request_events = [
                    event for event in journal.iter_events(0)
                    if str(getattr(event, "stream_id", "")) == f"run/{body.get('run_id')}"
                    and isinstance(getattr(event, "payload", None), Mapping)
                ]
            finally:
                journal.close()
        except Exception as error:
            raise PermissionError("review request cancellation state could not be reopened") from error
        if any(
            event.payload.get("schema") == "CODE_MODE_REVIEW_CANCELLED_V1"
            and event.payload.get("reference_id") == reference_id
            and event.payload.get("content_hash") == content_hash
            for event in request_events
        ):
            raise PermissionError("review request was cancelled")
        expiry_ok = type(body.get("tty_expires_at")) is int and body["tty_expires_at"] > int(time.time())
        accepted_expiry_ok = (
            type(accepted_at) is int and accepted_at > 0
            and type(body.get("tty_expires_at")) is int
            and accepted_at <= body["tty_expires_at"]
        )
        if (
            not isinstance(body.get("tty_nonce"), str) or not body.get("tty_nonce")
            or not expiry_ok and not accepted_expiry_ok
        ):
            raise PermissionError("review request TTY nonce is missing or expired")
        # The CAS body is deliberately locator-free.  Only this verified
        # in-memory projection may carry the exact source locator onward to
        # the TTY authority; callers cannot replace it with an arbitrary
        # request key.
        reopened = dict(body)
        reopened["reference_id"] = reference_id
        reopened["content_hash"] = content_hash
        reopened["object_hash"] = object_ref.object_id
        reopened["payload_hash"] = content_hash
        reopened["plaintext_commitment"] = proof.object_ref.plaintext_commitment
        return reopened

    def seal_candidate_manifest(
        self,
        *,
        candidate: Mapping[str, Any],
        run_id: str,
        journal: Any,
        cas: Any,
        run_stream: Any,
    ) -> dict[str, Any]:
        """Publish the controller's current candidate as an opaque locator.

        The interactive layer receives only this locator.  The candidate body
        is produced by the controller from the selected workspace at the
        execution-evidence boundary (after the verified patch and cleanup) and
        is reopened by the same runtime before review; it is never assembled
        from result scalars at the CLI boundary.
        """
        self._assert_bound_root()
        if not isinstance(candidate, Mapping) or candidate.get("candidate_id") is None:
            raise PermissionError("Code Mode candidate manifest is incomplete")
        if not isinstance(run_id, str) or not run_id.strip():
            raise PermissionError("Code Mode candidate run binding is missing")
        body = dict(candidate)
        body["schema"] = "CODE_MODE_CANDIDATE_MANIFEST_V1"
        body["run_id"] = run_id
        body.pop("content_hash", None)
        content_hash = candidate_payload_hash(body)
        body["content_hash"] = content_hash
        publication = cas.publish_plaintext(
            canonical_json_bytes(body),
            tenant_id="code-mode-evidence",
            purpose_class="code-mode-candidate-manifest",
            media_type="application/json",
        )
        receipt = publication.receipt
        if not receipt.fresh_verified or not receipt.no_replace_published:
            raise PermissionError("Code Mode candidate publication was not immutable")
        _fact, refs = run_stream.append_code_mode_fact(
            "code-mode-candidate-manifest",
            ({
                "schema": "CODE_MODE_CANDIDATE_MANIFEST_FACT_V1",
                "event_type": "code-mode.candidate-manifest",
                "purpose_class": "code-mode-candidate-manifest",
                "run_id": run_id,
                    "candidate_id": body.get("candidate_id"),
                    "tree_hash": body.get("tree_hash"),
                    "source_manifest_hash": body.get("source_manifest_hash"),
                "session_instance_id": body.get("session_instance_id"),
                "run_attempt": body.get("run_attempt"),
                    "authorization_ref": body.get("authorization_ref"),
                    "generation": body.get("generation"),
                    "session_id": body.get("session_id"),
                    "turn_index": body.get("turn_index"),
                    "reference_id": receipt.object_ref.reference_id,
                "content_hash": content_hash,
                "_object_refs": [receipt.object_ref.reference_id],
            },),
            actor="code-mode-receipt-sealer",
            proofs=(receipt,),
        )
        if len(refs) != 1:
            raise PermissionError("Code Mode candidate fact was not unique")
        return {
            "schema": "CODE_MODE_CANDIDATE_LOCATOR_V1",
            "reference_id": receipt.object_ref.reference_id,
            "content_hash": content_hash,
            "receipt_hash": content_hash,
            "object_hash": receipt.object_ref.object_id,
            "payload_hash": content_hash,
            "plaintext_commitment": receipt.object_ref.plaintext_commitment,
            "run_id": run_id,
            "candidate_id": body.get("candidate_id"),
            "tree_hash": body.get("tree_hash"),
            "authorization_ref": body.get("authorization_ref"),
            "journal_event_hash": refs[0]["event_hash"],
            "fresh_verified": True,
            "no_replace_published": True,
        }

    def reopen_candidate_manifest(self, locator: Mapping[str, Any], *, run_id: str) -> dict[str, Any]:
        """Reopen and verify a controller-issued candidate locator."""
        self._assert_bound_root()
        if not isinstance(locator, Mapping):
            raise PermissionError("Code Mode candidate locator is required")
        reference_id = locator.get("reference_id")
        content_hash = locator.get("content_hash")
        if (
            not isinstance(reference_id, str) or not reference_id.startswith("cas:")
            or not isinstance(content_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", content_hash)
            or locator.get("run_id") != run_id
        ):
            raise PermissionError("Code Mode candidate locator binding is invalid")
        cas = self.open_cas_reader()
        try:
            object_ref = cas.resolve_reference(reference_id)
            proof = cas.verify_existing(object_ref)
            if not proof.fresh_verified or not proof.no_replace_published:
                raise PermissionError("Code Mode candidate CAS proof is not fresh and no-replace")
            body = parse_canonical_json(cas.open_verified(object_ref))
        except PermissionError:
            raise
        except Exception as error:
            raise PermissionError("Code Mode candidate could not be reopened") from error
        if (
            not isinstance(body, Mapping)
            or body.get("schema") != "CODE_MODE_CANDIDATE_MANIFEST_V1"
            or body.get("run_id") != run_id
            or body.get("content_hash") != content_hash
            or candidate_payload_hash(body) != content_hash
            or body.get("candidate_id") != locator.get("candidate_id")
            or body.get("tree_hash") != locator.get("tree_hash")
        ):
            raise PermissionError("Code Mode candidate manifest binding is invalid")
        reopened = dict(body)
        reopened["reference_id"] = reference_id
        reopened["object_hash"] = object_ref.object_id
        reopened["payload_hash"] = content_hash
        reopened["plaintext_commitment"] = object_ref.plaintext_commitment
        return reopened

    def _verify_code_mode_preterminal_stage(
        self,
        locator: Mapping[str, Any],
        *,
        run_id: str,
        stage: str,
    ) -> dict[str, Any]:
        """Verify a pre-root stage from current durable facts only."""
        if not isinstance(locator, Mapping) or locator.get("run_id") != run_id:
            raise PermissionError("Code Mode stage locator is not bound to this run")
        journal = self.open_runtime_state_reader()
        try:
            events = tuple(
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
            )
        finally:
            journal.close()
        checkpoints = [
            event for event in events
            if isinstance(getattr(event, "payload", None), Mapping)
            and event.payload.get("schema") == "CODE_MODE_REVIEW_PENDING_CHECKPOINT_V1"
        ]
        accepted = [
            event for event in events
            if isinstance(getattr(event, "payload", None), Mapping)
            and event.payload.get("schema") == "CODE_MODE_REVIEW_ACCEPTED_V1"
        ]
        terminals = [
            event for event in events
            if isinstance(getattr(event, "payload", None), Mapping)
            and event.payload.get("event_type") == "code-mode.terminal-success"
        ]
        request_ref = locator.get("review_request_ref") or locator.get("request_ref")
        if not isinstance(request_ref, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", request_ref):
            raise PermissionError("Code Mode stage locator has no review request")
        if not checkpoints or sum(1 for item in checkpoints if item.payload.get("request_ref") == request_ref) != 1:
            raise PermissionError("Code Mode review-pending checkpoint is not unique")
        if stage == "PENDING":
            if accepted or terminals:
                raise PermissionError("Code Mode PENDING stage has advanced facts")
        elif stage == "ACCEPTED":
            if len(accepted) != 1 or terminals:
                raise PermissionError("Code Mode ACCEPTED stage is not the exact next state")
            if accepted[0].payload.get("request_ref") != request_ref:
                raise PermissionError("Code Mode accepted fact request binding changed")
        elif stage == "TERMINALIZED":
            if len(accepted) != 1 or len(terminals) != 1:
                raise PermissionError("Code Mode TERMINALIZED stage is incomplete")
            terminal = terminals[0]
            if terminal.payload.get("terminal_state") != "SUCCEEDED":
                raise PermissionError("Code Mode terminalized stage is not successful")
            if locator.get("terminal_event_id") not in {None, terminal.event_id}:
                raise PermissionError("Code Mode terminal event binding changed")
        else:
            raise PermissionError("unknown Code Mode stage")
        return {
            "stage": stage,
            "run_id": run_id,
            "request_ref": request_ref,
            "checkpoint_event_id": checkpoints[0].event_id,
            "accepted_event_id": accepted[0].event_id if accepted else None,
            "terminal_event_id": terminals[0].event_id if terminals else None,
        }

    def verify_code_mode_reviewed_state(
        self,
        locator: Mapping[str, Any],
        *,
        run_id: str,
        stage: str = "ROOTED",
    ) -> dict[str, Any]:
        """Verify one authenticated Code Mode terminal state.

        This is the single verifier used by live finalization, recovery and
        existing-root idempotency.  The legacy-sounding reopen method below
        is only a compatibility delegate; it does not implement a second
        validation path.
        """
        if stage not in {"PENDING", "ACCEPTED", "TERMINALIZED", "ROOTED", "CONVERSATION_COMMITTED"}:
            raise PermissionError("unsupported Code Mode terminal verification stage")
        self._assert_bound_root()
        if not isinstance(locator, Mapping):
            raise PermissionError("reviewed Code Mode receipt locator is required")
        if stage in {"PENDING", "ACCEPTED", "TERMINALIZED"}:
            return self._verify_code_mode_preterminal_stage(locator, run_id=run_id, stage=stage)
        reference_id = locator.get("reference_id")
        expected_hash = str(locator.get("content_hash") or "").removeprefix("sha256:")
        if (
            not isinstance(reference_id, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", reference_id)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_hash)
            or locator.get("receipt_hash") != locator.get("content_hash")
            or locator.get("run_id") != run_id
        ):
            raise PermissionError("reviewed Code Mode receipt locator is invalid")
        cas = self.open_cas_reader()
        try:
            object_ref = cas.resolve_reference(reference_id)
            proof = cas.verify_existing(object_ref)
            if not proof.fresh_verified or not proof.no_replace_published:
                raise PermissionError("reviewed Code Mode receipt is not fresh and no-replace")
            body = json.loads(cas.open_verified(object_ref).decode("utf-8"))
        except PermissionError:
            raise
        except Exception as error:
            raise PermissionError("reviewed Code Mode receipt could not be reopened") from error
        if not isinstance(body, Mapping) or body.get("schema") != "CODE_MODE_REVIEWED_TERMINAL_RECEIPT_V1":
            raise PermissionError("reviewed Code Mode receipt schema is invalid")
        body_hash = str(body.get("content_hash") or "").removeprefix("sha256:")
        if body_hash != expected_hash or hashlib.sha256(
            canonical_json_bytes({key: value for key, value in body.items() if key != "content_hash"})
        ).hexdigest() != expected_hash:
            raise PermissionError("reviewed Code Mode receipt content identity changed")
        required_body_fields = (
            "session_id", "candidate_id", "tree_hash", "source_manifest_hash", "worktree_digest",
            "machine_check_ref", "machine_check_hash", "evidence_package_ref", "evidence_package_hash",
            "review_request_ref", "review_request_hash", "tty_review_receipt_ref",
            "tty_review_receipt_hash", "gate_status", "gate_identity", "generation",
            "verifier_identity", "execution_core_ref", "execution_core_hash", "user_response_hash",
            "conversation_message_hash", "terminal_event_id", "terminal_event_hash",
        )
        if (
            body.get("run_id") != run_id
            or body.get("status") != "SUCCEEDED"
            or any(not isinstance(body.get(field), str) or not body.get(field) for field in required_body_fields)
            or body.get("gate_status") != "CODE_MODE_READY"
            or not (
                (
                    isinstance(body.get("completion_plan_ref"), str)
                    and bool(body.get("completion_plan_ref"))
                    and isinstance(body.get("completion_plan_hash"), str)
                    and bool(body.get("completion_plan_hash"))
                )
                or (body.get("completion_plan_ref") is None and body.get("completion_plan_hash") is None)
            )
        ):
            raise PermissionError("reviewed Code Mode receipt run binding is invalid")
        journal = self.open_runtime_state_reader()
        try:
            roots = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("schema") == "CODE_MODE_FINAL_ROOT_V2"
                and event.payload.get("final_receipt_ref") == reference_id
                and event.payload.get("final_receipt_hash") == body.get("content_hash")
            ]
            terminals = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("event_type") == "code-mode.terminal-success"
                and event.payload.get("terminal_state") == "SUCCEEDED"
            ]
            reviewer_facts = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("schema") == "CODE_MODE_FINAL_REVIEWER_FACT_V1"
            ]
            accepted_facts = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
                and isinstance(getattr(event, "payload", None), Mapping)
                and event.payload.get("schema") == "CODE_MODE_REVIEW_ACCEPTED_V1"
            ]
            stream_events = [
                event for event in journal.iter_events(0)
                if str(getattr(event, "stream_id", "")) == f"run/{run_id}"
            ]
        finally:
            journal.close()
        if len(roots) != 1 or len(terminals) != 1:
            raise PermissionError("reviewed Code Mode receipt closing lineage is not unique")
        if len(reviewer_facts) != 1 or len(accepted_facts) != 1:
            raise PermissionError("reviewed Code Mode acceptance pair is not unique")
        reviewer_fact = reviewer_facts[0]
        accepted_fact = accepted_facts[0]
        reviewer_command = str(reviewer_fact.payload.get("causation_command_id") or "")
        if (
            reviewer_command == ""
            or accepted_fact.payload.get("causation_command_id") != reviewer_command
            or accepted_fact.position != reviewer_fact.position + 1
            or getattr(journal, "_position_hash", {}).get(reviewer_fact.position)
            != getattr(journal, "_position_hash", {}).get(accepted_fact.position)
            or accepted_fact.payload.get("accepted_at") != reviewer_fact.payload.get("accepted_at")
            or accepted_fact.payload.get("request_ref") != body.get("review_request_ref")
            or accepted_fact.payload.get("request_hash") != body.get("review_request_hash")
            or accepted_fact.payload.get("review_receipt_ref") != body.get("tty_review_receipt_ref")
            or accepted_fact.payload.get("review_receipt_hash") != body.get("tty_review_receipt_hash")
            or accepted_fact.payload.get("gate_status") != "CODE_MODE_READY"
        ):
            raise PermissionError("reviewed Code Mode acceptance pair binding is invalid")
        # Reopen the independent reviewer receipt instead of trusting the
        # accepted event's copied time fields.  Durable acceptance may be
        # recovered after its original TTL, but its signed confirmed_at must
        # have been valid at the time of acceptance.
        review_ref = body.get("tty_review_receipt_ref")
        review_hash = str(body.get("tty_review_receipt_hash") or "")
        try:
            review_object = cas.resolve_reference(str(review_ref))
            review_proof = cas.verify_existing(review_object)
            review_body = parse_canonical_json(cas.open_verified(review_object))
        except Exception as error:
            raise PermissionError("reviewed Code Mode reviewer receipt could not be reopened") from error
        if (
            not review_proof.fresh_verified
            or not review_proof.no_replace_published
            or not isinstance(review_body, Mapping)
            or review_body.get("schema") != "CODE_MODE_REVIEW_RECEIPT_V2"
            or review_body.get("content_hash") != review_hash
            or review_body.get("decision") != "ACCEPT"
            or review_body.get("review_request_ref") != body.get("review_request_ref")
            or type(review_body.get("confirmed_at")) is not int
            or type(review_body.get("expires_at")) is not int
            or int(review_body["confirmed_at"]) > int(review_body["expires_at"])
            or accepted_fact.payload.get("accepted_at") != review_body.get("confirmed_at")
        ):
            raise PermissionError("reviewed Code Mode reviewer time or binding is invalid")
        root = roots[0]
        root_payload = root.payload
        authority_command = str(root_payload.get("causation_command_id") or "")
        terminal_command = str(terminals[0].payload.get("causation_command_id") or "")
        authority_checker = getattr(journal, "is_authenticated_authority_command", None)
        if not callable(authority_checker) or not authority_checker(reviewer_command, stream_id=f"run/{run_id}"):
            raise PermissionError("reviewed Code Mode acceptance has no durable authority transaction")
        if not callable(authority_checker) or not authority_checker(authority_command, stream_id=f"run/{run_id}"):
            raise PermissionError("reviewed Code Mode root has no durable authority transaction")
        if not authority_checker(terminal_command, stream_id=f"run/{run_id}"):
            raise PermissionError("reviewed Code Mode terminal has no durable authority transaction")
        # A pre-acceptance reviewed receipt cannot contain the future plan
        # locator without a self-reference.  For that form, recover the
        # authenticated plan binding from the final-root event; if the body
        # carries a plan it must still agree with the root exactly.
        plan_ref = body.get("completion_plan_ref") or root_payload.get("completion_plan_ref")
        plan_hash = str(body.get("completion_plan_hash") or root_payload.get("completion_plan_hash") or "")
        if not isinstance(plan_ref, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", plan_ref) or not re.fullmatch(r"[0-9a-f]{64}", plan_hash):
            raise PermissionError("reviewed Code Mode receipt has no completion plan binding")
        try:
            plan_object = cas.resolve_reference(plan_ref)
            plan_proof = cas.verify_existing(plan_object)
            plan_body = parse_canonical_json(cas.open_verified(plan_object))
        except Exception as error:
            raise PermissionError("reviewed Code Mode completion plan could not be reopened") from error
        if not isinstance(plan_body, Mapping) or plan_body.get("schema") != "CODE_MODE_COMPLETION_PLAN_V1":
            raise PermissionError("reviewed Code Mode completion plan schema is invalid")
        computed_plan_hash = hashlib.sha256(
            canonical_json_bytes({key: value for key, value in plan_body.items() if key != "content_hash"})
        ).hexdigest()
        if plan_body.get("content_hash") != plan_hash or computed_plan_hash != plan_hash:
            raise PermissionError("reviewed Code Mode completion plan content identity is invalid")
        if plan_body.get("run_id") != run_id or plan_body.get("stream_id") != f"run/{run_id}":
            raise PermissionError("reviewed Code Mode completion plan run binding is invalid")
        if not plan_proof.fresh_verified or not plan_proof.no_replace_published:
            raise PermissionError("reviewed Code Mode completion plan CAS proof is invalid")
        plan_reference = getattr(plan_proof, "object_ref", None)
        if (
            plan_reference is None
            or plan_reference.reference_id != plan_ref
            or plan_reference.object_id != plan_ref.removeprefix("cas:")
            or not isinstance(plan_reference.plaintext_commitment, str)
            or not plan_reference.plaintext_commitment
            or not isinstance(plan_reference.commitment_key_id, str)
            or not plan_reference.commitment_key_id
            or not isinstance(plan_reference.profile, str)
            or not plan_reference.profile
            or getattr(plan_proof, "purpose_class", None) != "code-mode-completion-plan"
            or not isinstance(getattr(plan_proof, "core_header_hash", None), str)
            or not getattr(plan_proof, "core_header_hash", "")
            or not isinstance(getattr(plan_proof, "envelope_id", None), str)
            or not getattr(plan_proof, "envelope_id", "")
        ):
            raise PermissionError("reviewed Code Mode completion plan CAS identity is not exact")
        if not isinstance(plan_body.get("operations"), list) or len(plan_body["operations"]) != 3:
            raise PermissionError("reviewed Code Mode completion plan operations are invalid")
        plan_signature = plan_body.get("authority_signature_hex")
        plan_key_id = plan_body.get("issuer_key_id")
        plan_unsigned = {
            key: value for key, value in plan_body.items()
            if key not in {"content_hash", "authority_signature_hex"}
        }
        try:
            signature_valid = (
                isinstance(plan_key_id, str)
                and isinstance(plan_signature, str)
                and self._verify_host_signature(
                    plan_key_id, canonical_json_bytes(plan_unsigned), bytes.fromhex(plan_signature)
                )
            )
        except (ValueError, TypeError):
            signature_valid = False
        if not signature_valid:
            raise PermissionError("reviewed Code Mode completion plan signature is invalid")
        plan_operations = plan_body["operations"]
        operation_by_name = {
            str(item.get("operation")): item for item in plan_operations
            if isinstance(item, Mapping)
        }
        if set(operation_by_name) != {
            "LOGICAL_TERMINAL_OPERATION_V1",
            "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1",
            "LOGICAL_CONVERSATION_COMPLETION_V1",
        } or any(
            not isinstance(item.get("logical_operation_id"), str)
            or not isinstance(item.get("logical_operation_hash"), str)
            or not re.fullmatch(r"code-mode-op-[0-9a-f]{32}", item["logical_operation_id"])
            or not re.fullmatch(r"[0-9a-f]{64}", item["logical_operation_hash"])
            for item in plan_operations if isinstance(item, Mapping)
        ):
            raise PermissionError("reviewed Code Mode completion plan logical identities are invalid")
        if root_payload.get("completion_plan_ref") != plan_ref or root_payload.get("completion_plan_hash") != plan_hash:
            raise PermissionError("reviewed Code Mode root is not bound to its completion plan")
        terminal_payload = terminals[0].payload
        terminal_ref = terminal_payload.get("evidence_package_ref")
        terminal_hash = str(terminal_payload.get("evidence_package_hash") or "")
        if not isinstance(terminal_ref, str) or not re.fullmatch(r"cas:[0-9a-f]{64}", terminal_ref) or not re.fullmatch(r"[0-9a-f]{64}", terminal_hash):
            raise PermissionError("reviewed Code Mode terminal has no evidence locator")
        try:
            terminal_object = cas.resolve_reference(terminal_ref)
            terminal_proof = cas.verify_existing(terminal_object)
            terminal_body = parse_canonical_json(cas.open_verified(terminal_object))
        except Exception as error:
            raise PermissionError("reviewed Code Mode terminal evidence could not be reopened") from error
        terminal_body_hash = str(terminal_body.get("content_hash") or "").removeprefix("sha256:") if isinstance(terminal_body, Mapping) else ""
        if (
            not isinstance(terminal_body, Mapping)
            or terminal_body.get("schema") != "CODE_MODE_TERMINAL_EVIDENCE_V1"
            or terminal_body_hash != terminal_hash
            or hashlib.sha256(canonical_json_bytes({key: value for key, value in terminal_body.items() if key != "content_hash"})).hexdigest() != terminal_hash
            or not terminal_proof.fresh_verified
            or not terminal_proof.no_replace_published
        ):
            raise PermissionError("reviewed Code Mode terminal evidence identity is invalid")
        terminal_binding = terminal_body.get("code_mode_terminal_binding")
        if not isinstance(terminal_binding, Mapping):
            raise PermissionError("reviewed Code Mode terminal evidence binding is missing")
        for field, expected in {
            "run_id": run_id,
            "session_id": body.get("session_id"),
            "candidate_id": body.get("candidate_id"),
            "tree_hash": body.get("tree_hash"),
            "source_manifest_hash": body.get("source_manifest_hash"),
            "worktree_digest": body.get("worktree_digest"),
            "machine_check_ref": body.get("machine_check_ref"),
            "machine_check_hash": body.get("machine_check_hash"),
            "evidence_package_ref": body.get("evidence_package_ref"),
            "evidence_package_hash": body.get("evidence_package_hash"),
            "review_request_ref": body.get("review_request_ref"),
            "review_request_hash": body.get("review_request_hash"),
            "tty_review_receipt_ref": body.get("tty_review_receipt_ref"),
            "tty_review_receipt_hash": body.get("tty_review_receipt_hash"),
            "gate_status": body.get("gate_status"),
            "generation": body.get("generation"),
            "verifier_identity": body.get("verifier_identity"),
            "execution_core_ref": body.get("execution_core_ref"),
            "execution_core_hash": body.get("execution_core_hash"),
            # The terminal semantic object is sealed before the completion
            # plan CAS exists.  The planned terminal operation binds the plan
            # and its draft; the terminal evidence itself must remain
            # deterministic and non-self-referential.
            "completion_plan_ref": "logical:completion-plan",
            "completion_plan_hash": "logical:completion-plan",
        }.items():
            if terminal_binding.get(field) != expected:
                raise PermissionError("reviewed Code Mode terminal evidence binding changed: " + field)
        if terminal_ref != terminal_payload.get("evidence_package_ref"):
            raise PermissionError("reviewed Code Mode terminal evidence locator changed")
        for event, operation_name in (
            (terminals[0], "LOGICAL_TERMINAL_OPERATION_V1"),
            (root, "LOGICAL_FINAL_ROOT_SEAL_OPERATION_V1"),
        ):
            operation = event.payload.get("authority_operation")
            planned = operation_by_name[operation_name]
            if (
                not isinstance(operation, Mapping)
                or operation.get("operation") != operation_name
                or operation.get("operation_id") != planned.get("logical_operation_id")
            ):
                raise PermissionError("reviewed Code Mode physical operation is not the signed logical operation")
            mapping_reader = getattr(journal, "authority_operation_mapping", None)
            if not callable(mapping_reader):
                raise PermissionError("reviewed Code Mode physical operation mapping is unavailable")
            mapping = mapping_reader(operation["operation_id"], stream_id=f"run/{run_id}")
            mapped_events = [
                candidate_event for candidate_event in stream_events
                if isinstance(candidate_event.payload, Mapping)
                and isinstance(candidate_event.payload.get("authority_operation"), Mapping)
                and candidate_event.payload["authority_operation"].get("operation_id")
                == operation["operation_id"]
            ]
            mapped_event_hashes = [candidate_event.event_hash for candidate_event in mapped_events]
            if (
                mapping.get("transaction_hash") != getattr(journal, "_position_hash", {}).get(event.position)
                or mapping.get("start_stream_version") != planned.get("expected_start_version")
                or mapping.get("end_stream_version") != planned.get("expected_end_version")
                or mapping.get("event_hashes") != mapped_event_hashes
                or event not in mapped_events
            ):
                raise PermissionError(
                    "reviewed Code Mode physical operation mapping is invalid: "
                    + str({
                        "operation": operation.get("operation_id"),
                        "mapping": mapping,
                        "event_version": event.stream_version,
                        "event_hash": event.event_hash,
                        "position_hash": getattr(journal, "_position_hash", {}).get(event.position),
                        "planned": planned,
                    })
                )
        if (
            root.event_type != "code-mode.final-root"
            or root_payload.get("schema") != "CODE_MODE_FINAL_ROOT_V2"
            or root_payload.get("event_type") != "code-mode.final-root"
            or root_payload.get("authenticated_seal") is not True
            or root_payload.get("finalization_transaction") is not True
            or root_payload.get("gate_status") != "CODE_MODE_READY"
            or root_payload.get("seal_command_id") != root_payload.get("causation_command_id")
            or not isinstance(root_payload.get("seal_command_id"), str)
            or not root_payload.get("seal_command_id", "").startswith("code-mode-final-root-")
            or root_payload.get("final_receipt_ref") != reference_id
            or root_payload.get("final_receipt_hash") != body.get("content_hash")
            or reference_id not in set(getattr(root, "object_refs", ()))
            or root_payload.get("seal_command_id") != (
                journal.authority_operation_mapping(
                    str(root_payload.get("authority_operation", {}).get("operation_id") or ""),
                    stream_id=f"run/{run_id}",
                ).get("command_id")
                if isinstance(root_payload.get("authority_operation"), Mapping)
                else None
            )
            or root.position <= terminals[0].position
            or not stream_events
            or root.position != max(event.position for event in stream_events)
        ):
            raise PermissionError("reviewed Code Mode receipt root is not an authenticated stream head")
        terminal_operation = operation_by_name.get("LOGICAL_TERMINAL_OPERATION_V1")
        logical_terminal_hash = (
            terminal_operation.get("stage_actual_event_projection_hash")
            if isinstance(terminal_operation, Mapping) else None
        )
        receipt_terminal_binding_ok = (
            body.get("terminal_event_id") == terminals[0].event_id
            and body.get("terminal_event_hash") == terminals[0].event_hash
        ) or (
            body.get("terminal_event_id") == "logical:terminal"
            and body.get("terminal_event_hash") == logical_terminal_hash
        )
        if (
            not receipt_terminal_binding_ok
            or root.payload.get("terminal_event_id") != terminals[0].event_id
            or root.payload.get("terminal_event_hash") != terminals[0].event_hash
        ):
            raise PermissionError("reviewed Code Mode receipt terminal binding is invalid")
        if stage == "CONVERSATION_COMMITTED":
            session_id = body.get("session_id")
            if not isinstance(session_id, str) or not session_id:
                raise PermissionError("conversation-complete receipt has no session binding")
            session_events = [
                event for event in journal.iter_events(0)
                if event.stream_id == f"session/{session_id}"
                and isinstance(event.payload, Mapping)
                and event.payload.get("schema") == "CODE_MODE_CONVERSATION_COMPLETION_V1"
                and event.payload.get("run_id") == run_id
                and event.payload.get("assistant_message_id") == f"{session_id}-assistant-{body.get('turn_index', '')}"
            ]
            if len(session_events) != 1:
                raise PermissionError("conversation completion operation is not unique")
            conversation_operation = session_events[0].payload.get("authority_operation")
            if not isinstance(conversation_operation, Mapping):
                raise PermissionError("conversation completion has no authority operation")
            mapping_reader = getattr(journal, "authority_operation_mapping", None)
            if not callable(mapping_reader):
                raise PermissionError("conversation completion mapping is unavailable")
            conversation_mapping = mapping_reader(
                str(conversation_operation.get("operation_id") or ""),
                stream_id=f"session/{session_id}",
            )
            conversation_plan = operation_by_name["LOGICAL_CONVERSATION_COMPLETION_V1"]
            if (
                conversation_operation.get("operation") != "LOGICAL_CONVERSATION_COMPLETION_V1"
                or conversation_operation.get("operation_id") != conversation_plan.get("logical_operation_id")
                or conversation_mapping.get("start_stream_version") != conversation_plan.get("expected_start_version")
                or conversation_mapping.get("end_stream_version") != conversation_plan.get("expected_end_version")
                or session_events[0].event_hash not in set(conversation_mapping.get("event_hashes") or ())
            ):
                raise PermissionError("conversation completion mapping is not the signed planned operation")
        reopened = dict(body)
        reopened["reference_id"] = reference_id
        reopened["root_event_id"] = root.event_id
        reopened["root_event_hash"] = root.event_hash
        return reopened

    def reopen_reviewed_terminal_receipt(self, locator: Mapping[str, Any], *, run_id: str) -> dict[str, Any]:
        """Compatibility delegate to the single Code Mode state verifier."""
        return self.verify_code_mode_reviewed_state(locator, run_id=run_id)

    def create_review_request(
        self,
        *,
        candidate: Mapping[str, Any],
        run_receipt_ref: Mapping[str, Any],
        evidence_package_ref: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a refs-only Review V2 request from controller observations.

        The caller supplies locators only.  The machine receipt and the
        evidence package are reopened from this runtime's CAS/Journal; no
        return code, findings, severity, or decision can be injected here.
        The package is a distinct controller-produced CAS object.  Passing the
        machine locator, omitting the package, or supplying a caller-created
        package is rejected.
        """
        if not isinstance(evidence_package_ref, Mapping):
            raise PermissionError("review request requires a distinct evidence package locator")
        if evidence_package_ref.get("reference_id") == run_receipt_ref.get("reference_id"):
            raise PermissionError("machine check cannot masquerade as the evidence package")
        machine = self._reopen_bound_test_receipt(candidate=candidate, test_receipt=run_receipt_ref)
        # The CAS body intentionally has no locator; retain the verified
        # locator only for binding the second package object.
        machine["reference_id"] = str(run_receipt_ref["reference_id"])
        machine["journal_event_hash"] = str(run_receipt_ref.get("journal_event_hash") or "")
        package_ref = evidence_package_ref.get("reference_id")
        package_hash = evidence_package_ref.get("content_hash")
        if not isinstance(package_ref, str) or not isinstance(package_hash, str):
            raise PermissionError("review request evidence package locator is incomplete")
        package = self._reopen_bound_evidence_package(
            candidate=candidate, machine=machine,
            evidence_package_ref={"reference_id": package_ref, "content_hash": package_hash},
        )
        request = dict(package)
        request.pop("content_hash", None)
        request.update({
            "schema": "CODE_MODE_REVIEW_REQUEST_V2",
            "machine_check_ref": str(run_receipt_ref["reference_id"]),
            "evidence_package_ref": package_ref,
            "machine_check_hash": str(machine.get("content_hash") or ""),
            "evidence_package_hash": package_hash,
            # TTY confirmation is derived from this durable request and is
            # valid only for one short-lived nonce.  The caller cannot choose
            # the terminal or summary.
            "tty_nonce": secrets.token_urlsafe(24),
            "tty_expires_at": min(int(time.time()) + 120, int(package.get("expires_at") or int(time.time()) + 120)),
        })
        if not request["machine_check_hash"] or request["evidence_package_hash"] == request["machine_check_hash"]:
            raise PermissionError("review request evidence package hash is not distinct")
        return self._publish_offline_evidence_receipt(request)

    def review_headless(
        self, *, candidate: Mapping[str, Any], review_request: Mapping[str, Any], reviewer_session: Any,
    ) -> Any:
        """Ask an independent reviewer session to consume a durable request."""
        if not isinstance(review_request, Mapping) or review_request.get("schema") != "CODE_MODE_REVIEW_REQUEST_V2":
            raise PermissionError("Review V2 requires a durable review request")
        if str(review_request.get("reference_id") or "") in self._cancelled_review_requests:
            raise PermissionError("Review V2 request was cancelled")
        request_body = self._reopen_offline_review_request(candidate=candidate, request=review_request)
        if not callable(getattr(reviewer_session, "_prepare_review", None)):
            raise PermissionError("offline reviewer requires an independent review session")
        self.register_reviewer_session(reviewer_session)
        # The CAS object intentionally does not contain its own locator.  Add
        # the verified locator only to the in-memory request sent to the
        # reviewer so its proof can carry the exact durable request ref.
        request_body["reference_id"] = str(review_request["reference_id"])
        capability = reviewer_session._prepare_review(request_body)
        self._review_request_by_capability[id(capability)] = dict(review_request)
        self._review_request_by_binding[
            (
                str(candidate.get("candidate_id") or ""),
                str(candidate.get("tree_hash") or ""),
                str(request_body.get("machine_check_hash") or ""),
                str(request_body.get("run_id") or ""),
            )
        ] = dict(review_request)
        return capability

    def confirm_tty(
        self,
        *,
        review: Any,
        candidate: Mapping[str, Any] | None = None,
        reviewer_session: Any,
    ) -> Any:
        from sitina.orchestrator.code_mode_reviewer import CodeModeReviewerSession
        if (
            not isinstance(review, Mapping)
            or not isinstance(reviewer_session, CodeModeReviewerSession)
            or not reviewer_session.is_attested_reviewer()
            or not callable(getattr(reviewer_session, "confirm_tty", None))
        ):
            raise PermissionError("TTY review requires an independent reviewer session")
        if not isinstance(candidate, Mapping):
            raise PermissionError("TTY review requires the controller's current candidate projection")
        request = self._reopen_offline_review_request(candidate=candidate, request=review)
        # CAS bodies intentionally omit their own locator.  The controller
        # must attach the already-verified locator to this in-memory projection
        # before the reviewer derives its nonce/request binding; otherwise a
        # valid production handoff would be bound to an empty request key.
        request["reference_id"] = str(review.get("reference_id") or "")
        if not request["reference_id"].startswith("cas:") or request["content_hash"] != review.get("content_hash"):
            raise PermissionError("TTY review request locator is unavailable")
        # The reviewer derives the displayed fields from this reopened
        # request.  No caller-provided summary or tty path is accepted.
        confirmation = reviewer_session.confirm_tty(request)
        from sitina.orchestrator.code_mode_reviewer import TTYReviewConfirmation
        if not isinstance(confirmation, TTYReviewConfirmation):
            raise PermissionError("TTY confirmation did not come from the production TTY authority")
        if getattr(confirmation, "_session", None) is not reviewer_session:
            raise PermissionError("TTY confirmation session binding is invalid")
        return self.seal_tty_reviewer_receipt(
            candidate={"candidate_id": request.get("candidate_id"), "tree_hash": request.get("tree_hash")},
            review_request=review,
            reviewer_session=reviewer_session,
            confirmation=confirmation,
        )

    def seal_tty_reviewer_receipt(
        self,
        *,
        candidate: Mapping[str, Any],
        review_request: Mapping[str, Any],
        reviewer_session: Any,
        confirmation: Any,
    ) -> dict[str, Any]:
        """Seal the independent TTY review path after durable nonce consume."""
        from sitina.orchestrator.code_mode_reviewer import TTYReviewConfirmation
        if not isinstance(confirmation, TTYReviewConfirmation):
            raise PermissionError("TTY review requires a real controlling-terminal confirmation")
        if getattr(confirmation, "_session", None) is not reviewer_session:
            raise PermissionError("TTY review session binding is invalid")
        if not callable(getattr(reviewer_session, "verify_tty_confirmation", None)) or not reviewer_session.verify_tty_confirmation(confirmation):
            raise PermissionError("TTY confirmation proof was not issued by the reviewer host")
        proof_issuer = str(getattr(confirmation, "_proof", {}).get("issuer_id") or "")
        session_issuer = str(
            getattr(reviewer_session, "identity", {}).get("issuer_id") or ""
        )
        if not proof_issuer or proof_issuer != session_issuer:
            raise PermissionError("TTY confirmation issuer is not bound to the reviewer session")
        request = self._reopen_offline_review_request(candidate=candidate, request=review_request)
        nonce = getattr(confirmation, "_nonce", "")
        summary = {
            key: request.get(key)
            for key in ("candidate_id", "tree_hash", "run_id", "evidence_package_ref", "evidence_package_hash")
        }
        summary["nonce"] = nonce
        summary["expires_at"] = request.get("tty_expires_at")
        summary_hash = hashlib.sha256(canonical_json_bytes(summary)).hexdigest()
        if (
            getattr(confirmation, "_request_key", None) != (request.get("reference_id"), request.get("content_hash"))
            or getattr(confirmation, "_summary_hash", None) != summary_hash
            or getattr(confirmation, "_expires_at", 0) != request.get("tty_expires_at")
            or getattr(confirmation, "_expires_at", 0) <= int(time.time())
        ):
            raise PermissionError("TTY confirmation does not match the reopened request")
        consumption = self._consume_tty_nonce(request=request, confirmation=confirmation)
        body = {
            "schema": "CODE_MODE_REVIEW_RECEIPT_V2",
            "candidate_id": request.get("candidate_id"),
            "tree_hash": request.get("tree_hash"),
            "run_id": request.get("run_id"),
            "authorization_ref": request.get("authorization_ref"),
            "session_instance_id": request.get("session_instance_id"),
            "session_id": request.get("session_id"),
            "turn_index": request.get("turn_index", request.get("conversation_turn_index")),
            "run_attempt": request.get("run_attempt"),
            "generation": request.get("generation"),
            "verifier_identity": request.get("verifier_identity"),
            "test_receipt_hash": request.get("machine_check_hash"),
            "machine_check_hash": request.get("machine_check_hash"),
            "evidence_package_hash": request.get("evidence_package_hash"),
            "source_manifest_hash": request.get("source_manifest_hash"),
            "worktree_before_hash": request.get("worktree_before_hash"),
            "worktree_after_hash": request.get("worktree_after_hash"),
            "diff_hash": request.get("diff_hash"),
            "review_request_ref": request.get("reference_id"),
            "review_request_hash": request.get("content_hash"),
            "tty_consumption_ref": consumption["reference_id"],
            "tty_consumption_hash": consumption["content_hash"],
            "tty_consumption_event_hash": consumption["journal_event_hash"],
            "tty_nonce_hash": consumption["nonce_hash"],
            "tty_consumption_id": consumption["consumption_id"],
            "review_evidence_hash": summary_hash,
            "reviewer_id": session_issuer,
            "reviewer_session_id": session_issuer,
            "tty_issuer_id": proof_issuer,
            # Preserve the independently issued, signed TTY proof as a
            # nested fact.  The controller may add lineage, but it cannot
            # replace the reviewer authority evidence with a self-reported
            # ACCEPT string.
            "tty_confirmation_proof": dict(getattr(confirmation, "_proof", {})),
            # The acceptance time is part of the authenticated confirmation
            # and is reused during recovery; terminalization must not invent
            # a new wall-clock timestamp on every retry.
            "confirmed_at": int(getattr(confirmation, "_confirmed_at", 0) or 0),
            "issued_at": int(
                (getattr(confirmation, "_proof", {}) or {}).get("issued_at")
                or getattr(confirmation, "_confirmed_at", 0)
                or 0
            ),
            "issuer_identity": "code-mode-tty-authority",
            "authority_class": "TTY_REVIEW_AUTHORITY",
            "decision": "ACCEPT",
            "verdict_decision": "ACCEPT",
            "severity": "NONE",
            "findings": [],
            "closing_root": False,
            "expires_at": request.get("tty_expires_at"),
        }
        return self._publish_offline_evidence_receipt(
            body, reviewer_session=reviewer_session, tty_confirmation=confirmation,
        )

    def cancel_review(self, *, review: Any, reviewer_session: Any) -> None:
        if not isinstance(review, Mapping):
            raise PermissionError("Review V2 cancellation requires its durable request locator")
        reference_id = review.get("reference_id")
        if not isinstance(reference_id, str) or not reference_id.startswith("cas:"):
            raise PermissionError("Review V2 cancellation locator is invalid")
        if not callable(getattr(reviewer_session, "is_attested_reviewer", None)) or not reviewer_session.is_attested_reviewer():
            raise PermissionError("review cancellation requires an independent reviewer session")
        request = self._reopen_offline_review_request(candidate={
            "candidate_id": review.get("candidate_id"), "tree_hash": review.get("tree_hash")
        }, request=review)
        # Keep the in-memory set as a fast local UX guard, but make cancellation
        # durable and authoritative in the same run Journal.
        self._cancelled_review_requests.add(reference_id)
        from sitina.orchestrator.true_multi_agent_runtime import CanonicalStream
        journal = self.open_runtime_writer()
        try:
            stream = CanonicalStream(journal, str(request["run_id"]), f"run/{request['run_id']}", self.identity.genesis_hash)
            stream.append(
                "review-cancelled",
                ({
                    "schema": "CODE_MODE_REVIEW_CANCELLED_V1",
                    "reference_id": reference_id,
                    "content_hash": request.get("content_hash"),
                    "candidate_id": request.get("candidate_id"),
                    "tree_hash": request.get("tree_hash"),
                    "run_id": request.get("run_id"),
                    "session_instance_id": request.get("session_instance_id"),
                    "run_attempt": request.get("run_attempt"),
                    "session_id": request.get("session_id"),
                    "turn_index": request.get("turn_index"),
                },),
                actor="code-mode-review-controller",
            )
        finally:
            journal.close()

    def prepare_offline_reviewer_review(
        self, *, candidate: Mapping[str, Any], test_receipt: Mapping[str, Any],
        evidence_package_ref: Mapping[str, Any], reviewer_session: Any,
    ) -> Any:
        """Reopen the test receipt and create a pending independent review.

        The returned capability is not a verdict.  A separate reviewer
        confirmation must consume it before the receipt sealer can proceed.
        """
        request = self.create_review_request(
            candidate=candidate, run_receipt_ref=test_receipt,
            evidence_package_ref=evidence_package_ref,
        )
        return self.review_headless(
            candidate=candidate, review_request=request, reviewer_session=reviewer_session,
        )

    def seal_offline_reviewer_receipt(
        self,
        *,
        candidate: Mapping[str, Any],
        test_receipt: Mapping[str, Any],
        reviewer_session: Any,
        reviewer_capability: Any,
        reviewer_approval: Any = None,
    ) -> dict[str, Any]:
        """Seal a receipt returned by a distinct, attested reviewer issuer.

        ``reviewer_id`` and ``decision`` intentionally are not parameters.
        A normal runtime caller cannot turn its own strings into reviewer
        evidence; the separate reviewer process owns those fields and
        consumes its capability exactly once.
        """
        if not isinstance(candidate, Mapping) or not candidate.get("candidate_id") or not candidate.get("tree_hash"):
            raise ValueError("offline reviewer receipt requires a candidate identity")
        if not isinstance(test_receipt, Mapping) or not isinstance(test_receipt.get("content_hash"), str):
            raise ValueError("offline reviewer receipt requires a test receipt binding")
        run_id = str(test_receipt.get("run_id") or f"offline-{self.identity.journal_id}")
        test_receipt_body = self._reopen_bound_test_receipt(candidate=candidate, test_receipt=test_receipt)
        if not callable(getattr(reviewer_session, "issue_receipt", None)):
            raise PermissionError("offline reviewer requires an independent reviewer session")
        self.register_reviewer_session(reviewer_session)
        proof = reviewer_session.issue_receipt(
            reviewer_capability,
            candidate_id=str(candidate["candidate_id"]),
            tree_hash=str(candidate["tree_hash"]),
            test_receipt_hash=str(test_receipt["content_hash"]),
            run_id=run_id,
            test_receipt=test_receipt_body,
            review_approval=reviewer_approval,
        )
        if not isinstance(proof, Mapping) or not reviewer_session.verify_receipt(proof):
            raise PermissionError("reviewer proof failed independent verification")
        request_locator = self._review_request_by_capability.get(id(reviewer_capability))
        if request_locator is None:
            request_locator = self._review_request_by_binding.get(
                (str(candidate["candidate_id"]), str(candidate["tree_hash"]), str(test_receipt["content_hash"]), run_id)
            )
        body = {
            "schema": "CODE_MODE_REVIEW_RECEIPT_V2",
            "candidate_id": str(candidate["candidate_id"]),
            "tree_hash": str(candidate["tree_hash"]),
            "test_receipt_hash": str(test_receipt["content_hash"]),
            "run_id": run_id,
            "review_request_ref": str(
                (request_locator or {}).get("reference_id") or ""
            ),
            "review_request_hash": str(
                (request_locator or {}).get("content_hash") or ""
            ),
        }
        if not body["review_request_ref"] or not body["review_request_hash"]:
            raise PermissionError("reviewer receipt requires the current Review V2 request")
        result = self._publish_offline_evidence_receipt(
            body, reviewer_proof=proof, reviewer_session=reviewer_session,
        )
        self._review_request_by_capability.pop(id(reviewer_capability), None)
        self._review_request_by_binding.pop(
            (str(candidate["candidate_id"]), str(candidate["tree_hash"]), str(test_receipt["content_hash"]), run_id),
            None,
        )
        return result

    def register_execution_parent(
        self,
        *,
        code_mode_authorization: Mapping[str, Any],
        execution_authorization: Mapping[str, Any],
        session_id: str,
        run_id: str,
        intent_hash: str,
        workspace: Path,
        scope: tuple[str, ...],
        expires_at: int,
        trusted_authorizer: CodeModeRuntimePolicy,
        authorization_message: str,
        risk_level: str,
    ) -> CodeModeExecutionParentBinding:
        """Register a trusted, immutable parent for sandbox child issuance."""

        if not isinstance(trusted_authorizer, CodeModeRuntimePolicy):
            raise PermissionError("sandbox parent requires the bound Code Mode issuer")
        token = code_mode_authorization.get("authorization_token")
        if not isinstance(token, str) or not token:
            raise PermissionError("Code Mode sandbox parent requires an opaque session authorization")
        if not trusted_authorizer.validate_issued_authorization(
            code_mode_authorization,
            mode=str(code_mode_authorization.get("mode") or ""),
            message=str(authorization_message),
            session_id=str(session_id),
            workspace=Path(workspace),
        ):
            raise PermissionError("sandbox parent requires a current issued Code Mode authorization")
        if execution_authorization.get("run_id") != run_id:
            raise PermissionError("sandbox parent run binding mismatch")
        if execution_authorization.get("session_id") != session_id:
            raise PermissionError("sandbox parent session binding mismatch")
        if execution_authorization.get("schema") != "SITINA_EXECUTION_AUTHORIZATION_V1":
            raise PermissionError("sandbox parent requires the canonical execution authorization")
        if execution_authorization.get("authorization_ref") in {None, ""}:
            raise PermissionError("sandbox parent requires an execution authorization reference")
        if execution_authorization.get("workspace") != str(Path(workspace).expanduser().resolve(strict=True)):
            raise PermissionError("sandbox parent target workspace mismatch")
        execution_scope = execution_authorization.get("scope")
        if not isinstance(execution_scope, (list, tuple)) or not execution_scope:
            raise PermissionError("sandbox parent requires an execution scope")
        canonical_scope_values: list[str] = []
        for item in scope:
            raw_scope = Path(item).expanduser()
            if raw_scope.is_symlink():
                raise PermissionError("sandbox parent scope cannot contain a symlink root")
            canonical_scope_values.append(str(raw_scope.resolve(strict=False)))
        canonical_scope = tuple(sorted(canonical_scope_values))
        canonical_execution_scope = tuple(sorted(
            str(Path(item).expanduser().resolve(strict=False)) for item in execution_scope
        ))
        if not set(canonical_scope).issubset(set(canonical_execution_scope)):
            raise PermissionError("sandbox parent scope cannot expand execution authorization")
        if str(Path(workspace).expanduser().resolve(strict=True)) not in canonical_scope:
            raise PermissionError("sandbox parent scope does not contain the selected workspace")
        execution_expires_at = int(execution_authorization.get("expires_at") or 0)
        code_expires_at = int(code_mode_authorization.get("expires_at") or 0)
        now = int(time.time())
        if int(expires_at) <= now or int(expires_at) > min(execution_expires_at, code_expires_at):
            raise PermissionError("sandbox parent lifetime exceeds an immutable authorization")
        if str(risk_level) != str(execution_authorization.get("risk_level") or ""):
            raise PermissionError("sandbox parent risk binding mismatch")
        session_instance_id = str(
            execution_authorization.get("session_instance_id") or self.session_instance_id
        ).strip()
        conversation_session_id = str(
            execution_authorization.get("conversation_session_id")
            or execution_authorization.get("session_id")
            or session_id
        ).strip()
        turn_index = execution_authorization.get("turn_index", 0)
        generation = str(
            execution_authorization.get("generation") or self.identity.epoch_root
        ).strip()
        provider_profile = str(
            execution_authorization.get("provider_profile") or "unbound"
        ).strip()
        provider_model = str(
            execution_authorization.get("provider_model") or "unbound"
        ).strip()
        if (
            not session_instance_id or not conversation_session_id or not generation
            or type(turn_index) is not int or turn_index < 0
            or not provider_profile or not provider_model
        ):
            raise PermissionError("sandbox parent authority scope is incomplete")
        issued_intent_hash = (code_mode_authorization.get("intent") or {}).get("intent_hash")
        if str(issued_intent_hash or "") != str(intent_hash):
            raise PermissionError("sandbox parent intent binding mismatch")
        try:
            canonical = execution_parent_projection(
                authorization_token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
                authorization_ref=str(execution_authorization.get("authorization_ref") or ""),
                session_instance_id=session_instance_id,
                conversation_session_id=conversation_session_id,
                turn_index=turn_index,
                generation=generation,
                provider_profile=provider_profile,
                provider_model=provider_model,
                session_id=str(session_id),
                run_id=str(run_id),
                intent_hash=str(intent_hash),
                workspace=str(Path(workspace).expanduser().resolve(strict=True)),
                scope=canonical_scope,
                risk_level=str(risk_level),
                # The parent is a run root. Attempts are derived below and
                # are never inherited from this root binding.
                attempt=0,
                expires_at=int(expires_at),
            )
        except Exception as error:
            raise PermissionError("sandbox parent projection is invalid") from error
        if canonical["expires_at"] <= int(time.time()):
            raise PermissionError("sandbox parent authorization is expired")
        parent_hash = execution_parent_hash(canonical)
        handle = secrets.token_urlsafe(32)
        self._execution_parents[handle] = dict(canonical) | {"handle": handle, "parent_hash": parent_hash}
        return CodeModeExecutionParentBinding(
            handle=handle,
            parent_hash=parent_hash,
            session_id=str(session_id),
            run_id=str(run_id),
            intent_hash=str(intent_hash),
            workspace=canonical["workspace"],
            scope=canonical["scope"],
            risk_level=canonical["risk_level"],
            attempt=0,
            expires_at=canonical["expires_at"],
        )

    def revoke_execution_parent(self, parent: CodeModeExecutionParentBinding) -> None:
        """Revoke a registered parent; all later child derivation is denied."""

        if type(parent) is not CodeModeExecutionParentBinding:
            raise PermissionError("invalid Code Mode parent capability")
        record = self._execution_parents.get(parent.handle)
        if not isinstance(record, Mapping) or record.get("parent_hash") != parent.parent_hash:
            raise PermissionError("unknown Code Mode parent capability")
        self._revoked_execution_parents.add(parent.handle)

    def issue_sandbox_child_capability(
        self,
        parent: CodeModeExecutionParentBinding,
        *,
        run_id: str,
        attempt: int,
        diff_hash: str,
        test_plan_hash: str,
        runner_executable: Path,
        worker_path: Path,
        cwd: Path,
        read_roots: tuple[Path, ...],
        write_roots: tuple[Path, ...],
        argv: tuple[str, ...],
        expires_at: int | None = None,
        now: int | None = None,
    ):
        from sitina.legacy.fence import _issue_trusted_code_mode_sandbox_capability

        moment = int(time.time()) if now is None else int(now)
        record = self._execution_parents.get(getattr(parent, "handle", ""))
        if (
            type(parent) is not CodeModeExecutionParentBinding
            or not isinstance(record, Mapping)
            or parent.handle in self._revoked_execution_parents
            or record.get("parent_hash") != parent.parent_hash
            or record.get("session_id") != parent.session_id
            or record.get("run_id") != parent.run_id
            or record.get("intent_hash") != parent.intent_hash
            or tuple(record.get("scope") or ()) != tuple(parent.scope)
            or record.get("risk_level") != parent.risk_level
            or str(run_id) not in {str(record.get("run_id")), str(record.get("run_id")) + ":probe"}
            or isinstance(attempt, bool)
            or not isinstance(attempt, int)
            or int(attempt) < 1
            or (parent.handle, str(run_id), int(attempt)) in self._issued_child_attempts
            or moment >= int(record.get("expires_at") or 0)
            or int(parent.expires_at) != int(record.get("expires_at") or 0)
        ):
            raise PermissionError("Code Mode sandbox parent is invalid, expired, or replayed")
        child_expiry = min(int(record["expires_at"]), moment + 120)
        if expires_at is not None and (int(expires_at) <= moment or int(expires_at) > child_expiry):
            raise PermissionError("Code Mode sandbox child expiry is outside the immutable parent lifetime")
        try:
            parent_roots = tuple(Path(item).resolve(strict=True) for item in record.get("scope") or ())
        except (OSError, RuntimeError) as error:
            raise PermissionError("Code Mode sandbox parent scope is unavailable") from error
        requested_paths = (cwd, *read_roots, *write_roots)
        try:
            canonical_requested = tuple(Path(item).expanduser().resolve(strict=True) for item in requested_paths)
        except (OSError, RuntimeError) as error:
            raise PermissionError("Code Mode sandbox child path cannot be resolved safely") from error
        if any(
            not any(path == root or root in path.parents for root in parent_roots)
            for path in canonical_requested
        ):
            raise PermissionError("Code Mode sandbox child scope would expand its parent")
        capability = _issue_trusted_code_mode_sandbox_capability(
            run_id=run_id,
            attempt=int(attempt),
            diff_hash=diff_hash,
            test_plan_hash=test_plan_hash,
            parent_authorization_hash=parent.parent_hash,
            runner_executable=runner_executable,
            worker_path=worker_path,
            cwd=cwd,
            read_roots=read_roots,
            write_roots=write_roots,
            argv=argv,
            expires_at=int(expires_at or child_expiry),
            now=moment,
        )
        self._issued_child_attempts.add((parent.handle, str(run_id), int(attempt)))
        return capability

    def register_execution_child_authorization(
        self,
        parent: CodeModeExecutionParentBinding,
        binding: Mapping[str, Any],
    ) -> str:
        """Register one exact Forge-attempt binding for mutation tooling.

        The mapping is persisted by the caller for evidence, but ToolExecutor
        accepts it only after this in-memory issuer has registered the exact
        canonical object.  This prevents model/control mappings and copied
        parent hashes from minting direct mutation capabilities.
        """

        if type(parent) is not CodeModeExecutionParentBinding:
            raise PermissionError("invalid Code Mode parent capability")
        record = self._execution_parents.get(parent.handle)
        if not isinstance(record, Mapping) or parent.handle in self._revoked_execution_parents:
            raise PermissionError("Code Mode execution parent is unavailable")
        if record.get("parent_hash") != parent.parent_hash:
            raise PermissionError("Code Mode execution parent hash mismatch")
        parent_fields = {
            "session_id": parent.session_id,
            "run_id": parent.run_id,
            "intent_hash": parent.intent_hash,
            "workspace": parent.workspace,
            "scope": tuple(parent.scope),
            "risk_level": parent.risk_level,
            "attempt": parent.attempt,
            "expires_at": parent.expires_at,
            "handle": parent.handle,
            "parent_hash": parent.parent_hash,
        }
        for field_name, expected_value in parent_fields.items():
            actual_value = record.get(field_name)
            if field_name == "scope":
                actual_value = tuple(actual_value or ())
            if actual_value != expected_value:
                raise PermissionError("Code Mode parent binding does not match canonical issuer record")
        if not isinstance(binding, Mapping) or binding.get("schema") != "SITINA_EXECUTION_CHILD_AUTHORIZATION_V1":
            raise PermissionError("Code Mode child authorization schema is invalid")
        attempt = binding.get("attempt")
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
            raise PermissionError("Code Mode child authorization attempt is invalid")
        if binding.get("parent_authorization_hash") != parent.parent_hash:
            raise PermissionError("Code Mode child authorization parent mismatch")
        if binding.get("parent_run_id") != parent.run_id:
            raise PermissionError("Code Mode child authorization root run mismatch")
        purpose = str(binding.get("purpose") or "")
        if purpose not in {"forge-attempt", "rejected-attempt-rollback", "accepted-patch-apply"}:
            raise PermissionError("Code Mode child authorization purpose is invalid")
        child_run_id = str(binding.get("run_id") or "")
        expected_prefix = {
            "forge-attempt": "forge-exec",
            "rejected-attempt-rollback": "rollback",
            "accepted-patch-apply": "apply",
        }[purpose]
        expected_run_id = f"{expected_prefix}-{parent.run_id}-{attempt}"
        if child_run_id != expected_run_id:
            raise PermissionError("Code Mode child authorization attempt run mismatch")
        if binding.get("session_id") != parent.session_id or binding.get("intent_hash") != parent.intent_hash:
            raise PermissionError("Code Mode child authorization session or intent mismatch")
        expected_workspace = str(Path(binding.get("workspace") or "").expanduser().resolve(strict=True))
        if expected_workspace not in parent.scope:
            raise PermissionError("Code Mode child authorization workspace expands parent scope")
        scope = binding.get("scope")
        if not isinstance(scope, list) or tuple(sorted(str(Path(item).expanduser().resolve(strict=True)) for item in scope)) != (expected_workspace,):
            raise PermissionError("Code Mode child authorization scope is not exact")
        if str(binding.get("risk_level") or "") != parent.risk_level:
            raise PermissionError("Code Mode child authorization risk mismatch")
        expected_parent = record
        required_scope = {
            "session_instance_id": expected_parent.get("session_instance_id"),
            "conversation_session_id": expected_parent.get("conversation_session_id"),
            "turn_index": expected_parent.get("turn_index"),
            "generation": expected_parent.get("generation"),
            "provider_profile": expected_parent.get("provider_profile"),
            "provider_model": expected_parent.get("provider_model"),
        }
        for field_name, expected_value in required_scope.items():
            actual_value = binding.get(field_name)
            if type(expected_value) is int:
                if type(actual_value) is not int or actual_value != expected_value:
                    raise PermissionError("Code Mode child authorization scope changed: " + field_name)
            elif not isinstance(actual_value, str) or actual_value != expected_value:
                raise PermissionError("Code Mode child authorization scope changed: " + field_name)
        expiry = int(binding.get("expires_at") or 0)
        if expiry <= int(time.time()) or expiry > parent.expires_at:
            raise PermissionError("Code Mode child authorization expiry is invalid")
        expected_ref = "execution-authorization-child:" + domain_hash(
            "SITINA_EXECUTION_CHILD_AUTHORIZATION",
            canonical_json_bytes({
                "parent_authorization_hash": parent.parent_hash,
                "parent_run_id": parent.run_id,
                "run_id": child_run_id,
                "attempt": attempt,
                "purpose": purpose,
                "session_instance_id": expected_parent.get("session_instance_id"),
                "conversation_session_id": expected_parent.get("conversation_session_id"),
                "turn_index": expected_parent.get("turn_index"),
                "generation": expected_parent.get("generation"),
                "provider_profile": expected_parent.get("provider_profile"),
                "provider_model": expected_parent.get("provider_model"),
                "execution_root": expected_workspace,
                "scope": [expected_workspace],
            }),
        )
        if binding.get("authorization_ref") != expected_ref:
            raise PermissionError("Code Mode child authorization reference is not issuer-derived")
        payload_hash = binding.get("payload_hash")
        unsigned_binding = {key: value for key, value in binding.items() if key != "payload_hash"}
        expected_payload_hash = hashlib.sha256(canonical_json_bytes(unsigned_binding)).hexdigest()
        if payload_hash != expected_payload_hash:
            raise PermissionError("Code Mode child authorization payload commitment is not exact")
        expected_binding = {
            "schema": "SITINA_EXECUTION_CHILD_AUTHORIZATION_V1",
            "parent_authorization_hash": parent.parent_hash,
            "parent_run_id": parent.run_id,
            "run_id": child_run_id,
            "attempt": attempt,
            "purpose": purpose,
            "session_instance_id": expected_parent.get("session_instance_id"),
            "conversation_session_id": expected_parent.get("conversation_session_id"),
            "turn_index": expected_parent.get("turn_index"),
            "generation": expected_parent.get("generation"),
            "session_id": parent.session_id,
            "intent_hash": parent.intent_hash,
            "workspace": expected_workspace,
            "execution_root": expected_workspace,
            "scope": [expected_workspace],
            "risk_level": parent.risk_level,
            "provider_profile": expected_parent.get("provider_profile"),
            "provider_model": expected_parent.get("provider_model"),
            "expires_at": expiry,
            "authorization_ref": expected_ref,
            "payload_hash": expected_payload_hash,
        }
        if dict(binding) != expected_binding:
            raise PermissionError("Code Mode child authorization differs from canonical issuer record")
        key = str(expected_ref)
        if key in self._execution_children:
            raise PermissionError("Code Mode child authorization was already registered")
        canonical = dict(binding)
        canonical["workspace"] = expected_workspace
        self._execution_children[key] = {
            "binding": canonical,
            "parent_handle": parent.handle,
        }
        return key

    def issue_execution_child_authorization(
        self,
        parent: CodeModeExecutionParentBinding,
        *,
        attempt: int,
        purpose: str,
        workspace: Path,
        scope: tuple[str, ...],
        expires_at: int,
    ) -> dict[str, Any]:
        """Issue and register one purpose-specific child from the trusted parent."""
        if type(parent) is not CodeModeExecutionParentBinding:
            raise PermissionError("invalid Code Mode parent capability")
        parent_record = self._execution_parents.get(parent.handle)
        if (
            not isinstance(parent_record, Mapping)
            or parent.handle in self._revoked_execution_parents
            or parent_record.get("parent_hash") != parent.parent_hash
        ):
            raise PermissionError("Code Mode execution parent is unavailable or changed")
        if purpose not in {"forge-attempt", "rejected-attempt-rollback", "accepted-patch-apply"}:
            raise PermissionError("Code Mode child authorization purpose is invalid")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise PermissionError("Code Mode child authorization attempt is invalid")
        expected_prefix = {
            "forge-attempt": "forge-exec",
            "rejected-attempt-rollback": "rollback",
            "accepted-patch-apply": "apply",
        }[purpose]
        workspace_value = str(Path(workspace).expanduser().resolve(strict=True))
        scope_values = [str(Path(item).expanduser().resolve(strict=True)) for item in scope]
        if scope_values != [workspace_value] or expires_at > parent.expires_at:
            raise PermissionError("Code Mode child scope or expiry expands the trusted parent")
        child_run_id = f"{expected_prefix}-{parent.run_id}-{attempt}"
        ref_body = {
            "parent_authorization_hash": parent.parent_hash,
            "parent_run_id": parent.run_id,
            "run_id": child_run_id,
            "attempt": attempt,
            "purpose": purpose,
            "session_instance_id": parent_record.get("session_instance_id"),
            "conversation_session_id": parent_record.get("conversation_session_id"),
            "turn_index": parent_record.get("turn_index"),
            "generation": parent_record.get("generation"),
            "provider_profile": parent_record.get("provider_profile"),
            "provider_model": parent_record.get("provider_model"),
            "execution_root": workspace_value,
            "scope": [workspace_value],
        }
        binding = {
            "schema": "SITINA_EXECUTION_CHILD_AUTHORIZATION_V1",
            "parent_authorization_hash": parent.parent_hash,
            "parent_run_id": parent.run_id,
            "run_id": child_run_id,
            "attempt": attempt,
            "purpose": purpose,
            "session_instance_id": parent_record.get("session_instance_id"),
            "conversation_session_id": parent_record.get("conversation_session_id"),
            "turn_index": parent_record.get("turn_index"),
            "generation": parent_record.get("generation"),
            "session_id": parent.session_id,
            "intent_hash": parent.intent_hash,
            "workspace": workspace_value,
            "execution_root": workspace_value,
            "scope": [workspace_value],
            "risk_level": parent.risk_level,
            "provider_profile": parent_record.get("provider_profile"),
            "provider_model": parent_record.get("provider_model"),
            "expires_at": int(expires_at),
            "authorization_ref": "execution-authorization-child:" + domain_hash(
                "SITINA_EXECUTION_CHILD_AUTHORIZATION", canonical_json_bytes(ref_body)
            ),
        }
        binding["payload_hash"] = hashlib.sha256(
            canonical_json_bytes({key: value for key, value in binding.items()})
        ).hexdigest()
        self.register_execution_child_authorization(parent, binding)
        return binding

    def validate_execution_child_authorization(
        self,
        binding: Mapping[str, Any],
        *,
        run_id: str,
        authorization_ref: str,
    ) -> bool:
        """Validate the exact child object registered by this context."""

        if not isinstance(binding, Mapping) or not isinstance(authorization_ref, str):
            return False
        entry = self._execution_children.get(authorization_ref)
        if not isinstance(entry, Mapping):
            return False
        expected = entry.get("binding")
        parent_handle = entry.get("parent_handle")
        if not isinstance(expected, Mapping) or dict(binding) != dict(expected):
            return False
        expected_run = str(expected.get("parent_run_id") or "")
        expected_attempt = int(expected.get("attempt") or 0)
        current_binding = self._request_binding
        if isinstance(current_binding, Mapping) and (
            current_binding.get("run_id") != expected_run
            or current_binding.get("run_attempt") != expected_attempt
        ):
            return False
        if (
            (expected_run, expected_attempt) in self._invalidated_code_mode_bindings
            or (
                str(self._request_binding.get("run_id") if self._request_binding else "") == expected_run
                and expected_attempt in self._invalidated_code_mode_attempts
            )
        ):
            return False
        if not isinstance(parent_handle, str) or parent_handle in self._revoked_execution_parents:
            return False
        parent_record = self._execution_parents.get(parent_handle)
        if not isinstance(parent_record, Mapping) or int(parent_record.get("expires_at") or 0) <= int(time.time()):
            return False
        if expected.get("run_id") != str(run_id):
            return False
        if str(expected.get("authorization_ref") or "") != authorization_ref:
            return False
        parent_ref = str(expected.get("parent_authorization_hash") or "")
        return bool(parent_ref) and int(expected.get("expires_at") or 0) > int(time.time())

    @property
    def events(self) -> tuple[Any, ...]:
        return ()

    def side_effect_counts(self, *, run_id: str | None = None, journal: Any | None = None) -> dict[str, Any]:
        """Derive side-effect counts from the current Code Mode Journal.

        SQLite bootstrap is intentionally reported as unknown because this
        context does not own a connection-level tracer.  Unknown is never
        converted into a false zero at the terminal boundary.
        """

        if not isinstance(run_id, str) or not run_id.strip():
            return {
                "legacy_read_count": None,
                "legacy_write_count": None,
                "acceptance_runtime_read_count": None,
                "sqlite_connect_count": None,
                "sqlite_write_count": None,
                "observation_status": "unknown-run",
            }
        try:
            if journal is not None:
                events = tuple(
                    event for event in journal.iter_events(0)
                    if isinstance(event.payload, Mapping)
                    and str(event.payload.get("run_id") or "") == run_id
                )
            else:
                journal = self.open_runtime_state_reader()
                try:
                    events = tuple(
                        event for event in journal.iter_events(0)
                        if isinstance(event.payload, Mapping)
                        and str(event.payload.get("run_id") or "") == run_id
                    )
                finally:
                    journal.close()
        except Exception:
            return {
                "legacy_read_count": None,
                "legacy_write_count": None,
                "acceptance_runtime_read_count": None,
                "sqlite_connect_count": None,
                "sqlite_write_count": None,
                "observation_status": "unavailable",
            }
        receipt_payload = {
            "schema": "CODE_MODE_SIDE_EFFECT_OBSERVATION_V1",
            "run_id": run_id,
            "event_ids": [str(event.event_id) for event in events],
            "event_count": len(events),
        }
        observation_receipt = hashlib.sha256(
            json.dumps(receipt_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return {
            "legacy_read_count": sum("legacy" in str(event.event_type).casefold() for event in events),
            "legacy_write_count": sum(
                "legacy" in str(event.event_type).casefold()
                and any(marker in str(event.event_type).casefold() for marker in ("write", "mutat", "delete"))
                for event in events
            ),
            "acceptance_runtime_read_count": sum("acceptance" in str(event.event_type).casefold() for event in events),
            "sqlite_connect_count": None,
            "sqlite_write_count": None,
            "observation_status": "journal-derived",
            "observed_event_count": len(events),
            "observed_event_ids": [str(event.event_id) for event in events],
            "observation_run_id": run_id,
            "observation_receipt": observation_receipt,
        }


def open_trusted_code_mode_context(*_args: Any, **_kwargs: Any) -> CodeModeRuntimeContext:
    """Deprecated public entry; trusted contexts require a bootstrap closure."""

    raise PermissionError(
        "trusted Code Mode contexts are only available from the CLI/Conversation bootstrap"
    )


class CodeModeScriptedProvider:
    """Explicit offline provider for the CLI integration path.

    It emits protocol-shaped responses but never opens a socket.  This is
    intentionally selected by an explicit ``--offline-scripted`` CLI option;
    it is not a live-provider fallback and cannot authorize a real canary.
    """

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace).resolve(strict=True)
        # Keep the endpoint identity shaped like the configured provider while
        # the client remains entirely local and never opens a network
        # connection.
        self.profile = ProviderProfile(
            "code-mode-scripted", "mock://offline", "", "scripted-code-mode",
            "openai_chat_completions",
        )
        self.text_calls = 0
        self.tool_calls = 0
        self.network_requests = 0
        self.physical_requests = 0
        self.tool_result_feedback_seen = False

    def load_profile(self, _name: str) -> ProviderProfile:
        return self.profile

    @staticmethod
    def _agent_id(system_prompt: str) -> str:
        match = re.search(r"Agent ([A-Za-z0-9-]+)", system_prompt)
        return match.group(1) if match else "scripted-agent"

    def _value(self, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        agent_id = self._agent_id(system_prompt)
        if "contract_hash=" in user_prompt and "selected_proposal_projection" in user_prompt:
            contract_match = re.search(r"contract_hash=([0-9a-f]{64})", user_prompt)
            projection_match = re.search(r'"selected_proposal_projection_hash"\s*:\s*"([0-9a-f]{64})"', user_prompt)
            if not contract_match or not projection_match:
                raise ValueError("scripted Handoff response lost its frozen binding")
            return {
                "agent_id": agent_id, "kind": "review", "accept": True,
                "reason": "The bounded read-only handoff is complete.",
                "missing_information": [], "contract_hash": contract_match.group(1),
                "generation": 1,
                "selected_proposal_projection_hash": projection_match.group(1),
            }
        if "Give the best direct answer" in user_prompt:
            return {
                "agent_id": agent_id,
                "kind": "conversation_answer",
                "answer": "RAG combines retrieval with generation so the model can ground its answer in relevant documents.",
                "confidence": "high",
                "needs_multi": False,
                "escalation_reasons": [],
            }
        if "Analyze this goal" in user_prompt:
            return {
                "agent_id": agent_id, "kind": "proposal", "complexity": "standard",
                "risk_level": "low", "protocols": ["proposal"], "task_graph": ["code-change"],
                "proposal_count": 1, "domain_capability": "python", "requires_rework": False,
                "requires_conflict": False, "requires_handoff_reject": False,
                "requires_reassignment": False, "requires_provider_unknown": False,
                "rationale": "A bounded offline Code Mode workspace change.",
            }
        if "Review only the completed Forge execution" in user_prompt or "Independently review this execution evidence" in user_prompt:
            return {
                "agent_id": agent_id, "kind": "review", "decision": "accept",
                "reason": "The actual diff and Tester evidence are present.",
                "evidence_checks": ["diff", "tests", "patch manifest"],
            }
        if "Round 2." in user_prompt:
            match = re.search(r"parent output hash is ([0-9a-f]{64})", user_prompt)
            if not match:
                raise ValueError("scripted Code Mode response lost its parent hash")
            return {
                "agent_id": agent_id, "kind": "proposal", "summary": "The bounded revision is valid.",
                "parent_output_hash": match.group(1),
                "defect_responses": ["addressed"] * 4,
                "acceptance_checks": ["focused test passes"] * 4,
            }
        if "Independently score" in user_prompt or "Re-review revision" in user_prompt or "Review round-2 revision hash" in user_prompt:
            return {"agent_id": agent_id, "kind": "review", "verdict": "approved", "score": 90,
                    "reason": "The bounded proposal is feasible and safe.", "defects": []}
        if "Create an independent solution" in user_prompt:
            return {"agent_id": agent_id, "kind": "proposal", "summary": "Create the requested file.",
                    "approach": "Use the approved workspace file tool and run the focused check.",
                    "risks": ["The change is limited to the selected workspace."],
                    "assumptions": ["The focused local test is available."],
                    "acceptance_checks": ["focused test passes"]}
        return {"agent_id": agent_id, "kind": "proposal", "summary": "Continue the bounded workspace plan.",
                "approach": "Use the selected workspace and verify the resulting diff.",
                "acceptance_checks": ["focused test passes"]}

    def _complete_openai(self, _profile: ProviderProfile, *, system_prompt: str, user_prompt: str, **_kwargs: Any) -> ProviderCompletion:
        self.text_calls += 1
        return ProviderCompletion(
            json.dumps(self._value(system_prompt, user_prompt), sort_keys=True),
            {"protocol": "openai_chat_completions", "provider_request_id": f"scripted-text-{self.text_calls}",
             "provider_response_id": f"scripted-response-{self.text_calls}",
             "token_usage": {"input_tokens": 4, "output_tokens": 6, "total_tokens": 10}},
        )

    def complete_tool_turn(self, _profile: ProviderProfile, *, messages: Any, **_kwargs: Any) -> ProviderToolTurn:
        self.tool_calls += 1
        if self.tool_calls > 1:
            self.tool_result_feedback_seen = any(
                isinstance(item, Mapping) and str(item.get("role") or "") in {"tool", "tool_result"}
                for item in messages
            )
            if not self.tool_result_feedback_seen:
                raise ValueError("scripted Code Mode provider did not receive tool feedback")
        if self.tool_calls == 1:
            return ProviderToolTurn(
                "", (ProviderToolCall("scripted-write-1", "sitina_write_file", {
                    "path": str(self.workspace / "hello.py"),
                    "content": (
                        "def hello():\n"
                        "    \"\"\"Return a greeting.\n\n"
                        "    >>> hello()\n"
                        "    'hello'\n"
                        "    \"\"\"\n"
                        "    return 'hello'\n"
                    ),
                }),), "tool_calls",
                {"protocol": "mock", "physical_send_count": 0,
                 "token_usage": {"input_tokens": 4, "output_tokens": 6, "total_tokens": 10}},
            )
        return ProviderToolTurn(
            "implemented and verified", (), "stop",
            {"protocol": "mock", "physical_send_count": 0,
             "token_usage": {"input_tokens": 4, "output_tokens": 6, "total_tokens": 10}},
        )
