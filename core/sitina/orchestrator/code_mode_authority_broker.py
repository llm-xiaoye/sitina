"""Narrow client for the external Code Mode authority host.

The issuer is intentionally not implemented in this importable module.
``scripts/code_mode_authority_host.py`` is started by the CLI host with an
inherited socketpair and a one-shot bootstrap FD. This module has no signing
key, no server, no launch method, and no generic RPC method.
"""
from __future__ import annotations

import atexit
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import threading
import secrets
import time
from pathlib import Path
from typing import Any, Mapping
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sitina.runners.provider import SUPPORTED_WIRE_PROTOCOLS


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class CodeModeAuthorityBrokerError(PermissionError):
    pass


class BrokerTransportCapability:
    __slots__ = ("_client", "_session", "_token")

    def __init__(self, client: "CodeModeAuthorityBroker", session: str, token: str):
        self._client, self._session, self._token = client, session, token


class BrokerTransportLedger:
    """Typed transport operations; the wire/RPC escape hatch is absent."""

    def __init__(self, client: "CodeModeAuthorityBroker", session: str, capability: BrokerTransportCapability):
        if capability._client is not client or capability._session != session:
            raise PermissionError("transport capability is not host-issued")
        self._client, self._session, self._capability = client, session, capability
        # A session may legitimately hold several non-interchangeable
        # authorization domains at once.  The active domain is selected only
        # by a typed bind method; a permit from one domain never overwrites
        # the durable record of another.
        self._authorization_domains: dict[str, dict[str, Any]] = {}
        # Execution and control authorizations are versioned by the durable
        # (run, attempt) scope.  The legacy flat fields below are only the
        # selected active projection sent with a request; they are never used
        # as the registry of prior attempts.
        self._attempt_authorization_domains: dict[str, dict[tuple[str, int], dict[str, Any]]] = {
            "attempt_execution": {}, "attempt_control": {},
        }
        self._active_authorization_domain: str | None = None
        self._authorization_id: str | None = None
        self._authorization_kind: str | None = None
        self._execution_authorization_ref: str | None = None
        self._execution_authorization_attempt: int | None = None

    def bind_canary_authorization(self, authorization: Mapping[str, Any]) -> None:
        authorization_id = str(authorization.get("authorization_id") or "")
        if not authorization_id:
            raise PermissionError("transport authorization is incomplete")
        prior = self._authorization_domains.get("post_review_canary")
        if prior is not None:
            if prior.get("authorization_id") != authorization_id:
                raise PermissionError("transport canary binding cannot be replaced")
            self._active_authorization_domain = "post_review_canary"
            self._authorization_id = authorization_id
            self._authorization_kind = "canary"
            return
        value = self._client._transport_bind(self._session, self._capability._token, authorization)
        if value.get("bound") is not True:
            raise PermissionError("transport canary binding was not accepted")
        self._authorization_id = authorization_id
        self._authorization_kind = "canary"
        self._authorization_domains["post_review_canary"] = {
            "authorization_id": authorization_id, "authorization": dict(authorization),
        }
        self._active_authorization_domain = "post_review_canary"

    def bind_pre_provider_authorization(self, authorization: Mapping[str, Any]) -> None:
        """Bind the separate pre-Forge Provider authorization domain."""
        authorization_id = str(authorization.get("authorization_id") or "")
        if not authorization_id or authorization.get("schema") != "CODE_MODE_PRE_PROVIDER_AUTHORIZATION_V1":
            raise PermissionError("pre-provider authorization is incomplete")
        prior = self._authorization_domains.get("pre_provider_root")
        if prior is not None:
            if prior.get("authorization_id") != authorization_id:
                raise PermissionError("transport authorization domain cannot be replaced")
            self._active_authorization_domain = "pre_provider_root"
            self._authorization_id = authorization_id
            self._authorization_kind = "pre-provider"
            return
        value = self._client._transport_bind_pre_provider(
            self._session, self._capability._token, authorization,
        )
        if value.get("bound") is not True:
            raise PermissionError("pre-provider authorization was not accepted")
        self._authorization_id = authorization_id
        self._authorization_kind = "pre-provider"
        self._execution_authorization_ref = None
        self._execution_authorization_attempt = int(authorization["run_attempt"])
        self._authorization_domains["pre_provider_root"] = {
            "authorization_id": authorization_id, "authorization": dict(authorization),
        }
        self._active_authorization_domain = "pre_provider_root"

    def bind_forge_execution_authorization(self, *, child_authorization_locator: str) -> dict[str, Any]:
        """Bind the current attempt-execution domain from a child locator.

        Run, attempt, parent and provider scope are deliberately absent from
        this API.  The authority host derives them by reopening the dedicated
        Journal/CAS child mapping, preventing a caller from selecting its own
        Forge scope.
        """
        if self._authorization_kind not in {"pre-provider", "forge-execution", "attempt-control"}:
            raise PermissionError("Forge authorization requires pre-provider admission")
        if not isinstance(child_authorization_locator, str) or not child_authorization_locator:
            raise PermissionError("Forge child authorization locator is required")
        value = self._client._transport_bind_forge(
            self._session, self._capability._token,
            child_authorization_locator=child_authorization_locator,
        )
        authorization_id = str(value.get("authorization_id") or "")
        authorization_ref = str(value.get("authorization_ref") or "")
        if not authorization_id or not authorization_ref:
            raise PermissionError("Forge authorization mapping is incomplete")
        attempt = value.get("run_attempt")
        run_id = str(value.get("run_id") or "")
        if type(attempt) is not int or attempt < 1 or not run_id:
            raise PermissionError("Forge authorization attempt is incomplete")
        prior_key = (run_id, attempt)
        prior = self._attempt_authorization_domains["attempt_execution"].get(prior_key)
        if isinstance(prior, Mapping) and prior.get("authorization_id") != authorization_id:
            raise PermissionError("Forge authorization mapping changed for this attempt")
        self._authorization_id = authorization_id
        self._authorization_kind = "forge-execution"
        self._execution_authorization_ref = authorization_ref
        self._execution_authorization_attempt = attempt
        record = {
            "authorization_id": authorization_id, "authorization": dict(value),
            "child_authorization_locator": child_authorization_locator,
        }
        self._attempt_authorization_domains["attempt_execution"][prior_key] = record
        self._authorization_domains["attempt_execution"] = record
        self._active_authorization_domain = "attempt_execution"
        return dict(value)

    def bind_attempt_control_authorization(self) -> dict[str, Any]:
        """Select the current post-Forge control domain from host facts."""
        if self._authorization_kind not in {"forge-execution", "attempt-control"}:
            raise PermissionError("attempt-control authorization requires Forge execution")
        # The registry is versioned by the complete (run, attempt) key.  A
        # flat attempt number is ambiguous when one controller services more
        # than one run, and using it here could return a control permit from a
        # sibling run.  Derive the key from the exact active Forge record,
        # which itself came from the host's locator-only child bind.
        active_execution = self._authorization_domains.get("attempt_execution")
        active_authorization = active_execution.get("authorization") if isinstance(active_execution, Mapping) else None
        root_run_id = str(active_authorization.get("run_id") or "") if isinstance(active_authorization, Mapping) else ""
        current_attempt = self._execution_authorization_attempt
        if not root_run_id or type(current_attempt) is not int or current_attempt < 1:
            raise PermissionError("attempt-control authorization has no exact Forge run scope")
        current_key = (root_run_id, current_attempt)
        prior = self._attempt_authorization_domains["attempt_control"].get(current_key)
        if prior is not None:
            authorization = prior.get("authorization")
            if not isinstance(authorization, Mapping):
                raise PermissionError("attempt-control mapping is invalid")
            self._authorization_id = str(prior.get("authorization_id") or "")
            self._authorization_kind = "attempt-control"
            self._execution_authorization_ref = str(authorization.get("authorization_ref") or "")
            self._execution_authorization_attempt = int(authorization.get("run_attempt") or 0)
            self._active_authorization_domain = "attempt_control"
            return dict(authorization)
        value = self._client._transport_bind_attempt_control(
            self._session, self._capability._token,
        )
        authorization_id = str(value.get("authorization_id") or "")
        authorization_ref = str(value.get("authorization_ref") or "")
        attempt = value.get("run_attempt")
        if not authorization_id or not authorization_ref or type(attempt) is not int or attempt < 1:
            raise PermissionError("attempt-control mapping is incomplete")
        self._authorization_id = authorization_id
        self._authorization_kind = "attempt-control"
        self._execution_authorization_ref = authorization_ref
        self._execution_authorization_attempt = attempt
        record = {
            "authorization_id": authorization_id, "authorization": dict(value),
        }
        run_id = str(value.get("run_id") or "")
        if run_id != root_run_id:
            raise PermissionError("attempt-control host mapping changed its Forge run")
        self._attempt_authorization_domains["attempt_control"][current_key] = record
        self._authorization_domains["attempt_control"] = record
        self._active_authorization_domain = "attempt_control"
        return dict(value)

    def begin(self, capability: object, **kwargs: Any) -> str:
        raise PermissionError("worker-side transport begin is forbidden; use host transport_send")

    def settle(self, capability: object, permit: object, **kwargs: Any) -> dict[str, Any]:
        raise PermissionError("worker-side transport settlement is forbidden; host transport_send owns settlement")

    def send(self, capability: object, **kwargs: Any) -> dict[str, Any]:
        if capability is not self._capability:
            raise PermissionError("transport capability is not host-issued")
        request = dict(kwargs)
        if self._authorization_id is not None:
            request["authorization_id"] = self._authorization_id
            request["authorization_kind"] = self._authorization_kind
            if self._execution_authorization_attempt is not None:
                request["attempt"] = self._execution_authorization_attempt
            if self._execution_authorization_ref is not None:
                request["execution_authorization_ref"] = self._execution_authorization_ref
        if self._active_authorization_domain is not None:
            request["authorization_domain"] = self._active_authorization_domain
        return self._client._transport_send(self._session, self._capability._token, request)

    def complete_tool_turn(self, capability: object, **kwargs: Any) -> dict[str, Any]:
        """Run one provider tool turn inside the host transport boundary.

        The worker/client supplies only the bound request projection.  The
        authority host performs HTTP, observes the response and usage, and
        atomically publishes the transport receipt.  There is deliberately no
        worker-side begin/settle pair for this operation.
        """
        if capability is not self._capability:
            raise PermissionError("transport capability is not host-issued")
        request = dict(kwargs)
        if self._authorization_id is not None:
            request["authorization_id"] = self._authorization_id
            request["authorization_kind"] = self._authorization_kind
            if self._execution_authorization_attempt is not None:
                request["attempt"] = self._execution_authorization_attempt
            if self._execution_authorization_ref is not None:
                request["execution_authorization_ref"] = self._execution_authorization_ref
        if self._active_authorization_domain is not None:
            request["authorization_domain"] = self._active_authorization_domain
        return self._client._transport_send(self._session, self._capability._token, request)

    def snapshot(self, capability: object) -> tuple[Mapping[str, Any], ...]:
        if capability is not self._capability:
            raise PermissionError("transport capability is not host-issued")
        return tuple(self._client._transport_snapshot(self._session, self._capability._token))

    def contains(self, receipt: Mapping[str, Any]) -> bool:
        return any(dict(item) == dict(receipt) for item in self.snapshot(self._capability))


class CodeModeAuthorityBroker:
    """Authenticated client connection to the CLI-owned host only.

    There is deliberately no ``launch``/``request``/``issue`` API. A client
    can be connected only to a process which passed host attestation in
    ``_connect_attested_host``. Constructing this class directly is inert.  This is a
    same-user CLI parent/child boundary, not a claim that Python code running
    as the same OS user is an adversary the package can independently defeat;
    stronger protection would require a separately installed OS trust root.
    """

    def __init__(
        self, channel: socket.socket, process: subprocess.Popen[bytes], identity: Mapping[str, Any],
        *, controller_capability_private_key: Ed25519PrivateKey | None = None,
    ):
        self._channel, self._process, self.identity = channel, process, dict(identity)
        self._attested = False
        self._closed = False
        self._lock = threading.RLock()
        self._reader, self._writer = channel.makefile("rb"), channel.makefile("wb")
        # The trusted CLI/controller owns this ephemeral signer.  The host
        # receives only its public half during the attested bind; workers and
        # ordinary runtime callers never receive the issuer object or key.
        from sitina.orchestrator.true_multi_agent_runtime import _ControllerCapabilityIssuer
        self._controller_capability_issuer = _ControllerCapabilityIssuer(
            controller_capability_private_key or Ed25519PrivateKey.generate()
        )
        atexit.register(self.close)

    # Deliberately module-private: only the fixed CLI launcher and the
    # test-only launcher seam may call this attestation handshake.  There is
    # no public caller-selected host connection or issuer factory.

    # These names intentionally hard-fail, including underscored names.
    def request(self, _request: Mapping[str, Any]) -> dict[str, Any]:
        raise PermissionError("raw authority RPC is unavailable to Code Mode clients")

    def _request(self, _request: Mapping[str, Any]) -> dict[str, Any]:
        raise PermissionError("raw authority RPC is unavailable to Code Mode clients")

    def issue_canary(self, _session: str, _body: Mapping[str, Any]) -> dict[str, Any]:
        raise PermissionError("canary issuance requires the CLI host admission path")

    def _issue_canary(self, _session: str, _body: Mapping[str, Any]) -> dict[str, Any]:
        raise PermissionError("canary issuance requires the CLI host admission path")

    def validate_canary(self, _session: str, _authorization: Mapping[str, Any]) -> bool:
        raise PermissionError("canary validation requires the bound runtime path")

    def _validate_canary(self, _session: str, _authorization: Mapping[str, Any]) -> bool:
        raise PermissionError("canary validation requires the bound runtime path")

    def consume_canary(self, _session: str, _authorization: Mapping[str, Any]) -> None:
        raise PermissionError("canary consumption requires the bound runtime path")

    def _consume_canary(self, _session: str, _authorization: Mapping[str, Any]) -> None:
        raise PermissionError("canary consumption requires the bound runtime path")

    def _rpc(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if not self._attested:
            raise PermissionError("authority host connection is not attested")
        with self._lock:
            self._writer.write(_canonical(dict(request)) + b"\n")
            self._writer.flush()
            line = self._reader.readline()
            if not line:
                raise CodeModeAuthorityBrokerError("authority host disconnected")
            response = json.loads(line.decode("utf-8"))
            if not response.get("ok"):
                detail = str(response.get("error") or "")[:180]
                # Preserve the provider's retry classification across the
                # authority boundary.  The host deliberately reports only a
                # status code marker; it never forwards provider response
                # bodies or credentials through this error path.
                response_status_code = response.get("status_code")
                if type(response_status_code) is int and 100 <= response_status_code <= 599:
                    from sitina.runners.provider import ProviderHTTPError

                    raise ProviderHTTPError(
                        response_status_code,
                        detail or "authority host HTTP failure",
                    )
                if detail.startswith("HTTP_STATUS_"):
                    marker, _, message = detail.partition(":")
                    try:
                        status_code = int(marker.removeprefix("HTTP_STATUS_"))
                    except ValueError:
                        status_code = 0
                    if status_code > 0:
                        from sitina.runners.provider import ProviderHTTPError

                        raise ProviderHTTPError(status_code, message.strip() or "authority host HTTP failure")
                raise CodeModeAuthorityBrokerError(
                    str(response.get("error_type") or "host request rejected")
                    + (": " + detail if detail else "")
                )
            value = response.get("value")
            if not isinstance(value, Mapping):
                raise CodeModeAuthorityBrokerError("authority host response is invalid")
            return dict(value)

    def is_attested_host_client(self) -> bool:
        """Return the local connection state; it is not an issuer credential."""
        return self._attested and not self._closed and self._process.poll() is None

    def bind_runtime(self) -> dict[str, Any]:
        """Bind the runtime using identities fixed in the CLI bootstrap.

        Runtime callers cannot select or replace the state root, Journal, or
        workspace identity over this RPC.  The host derives those values from
        the one-shot launcher bootstrap and reopens the bound state itself.
        """
        return self._rpc({
            "method": "bind",
            "controller_capability_public_key": self._controller_capability_issuer.public_key_bytes.hex(),
        })

    def read_binding(self, session: str) -> dict[str, Any]:
        return self._rpc({"method": "binding", "session": session})

    def read_provider_profile(self, profile: str) -> dict[str, Any]:
        """Return the complete non-secret host-observed profile summary.

        The host is the profile authority.  Keep this boundary strict so a
        custom OpenAI-compatible or Anthropic endpoint cannot silently lose
        its wire adapter or endpoint policy while crossing the broker.  The
        exact response shape also ensures credentials can never be forwarded
        as an accidental profile field.
        """
        if not isinstance(profile, str) or not profile.strip():
            raise PermissionError("provider profile name is required")
        value = self._rpc({"method": "profile_summary", "session": self._broker_session_for_profile(), "profile": profile})
        required = {
            "name", "base_url", "model", "wire_protocol",
            "adapter_capabilities", "allowed_endpoint_hosts",
        }
        if set(value) != required:
            raise CodeModeAuthorityBrokerError("provider profile summary shape is invalid")
        for field in ("name", "base_url", "model", "wire_protocol"):
            if type(value.get(field)) is not str or not value[field].strip():
                raise CodeModeAuthorityBrokerError("provider profile summary has an invalid " + field)
        if value["wire_protocol"] not in SUPPORTED_WIRE_PROTOCOLS:
            raise CodeModeAuthorityBrokerError("provider profile summary has an unsupported wire protocol")
        for field in ("adapter_capabilities", "allowed_endpoint_hosts"):
            items = value.get(field)
            if type(items) is not list or any(type(item) is not str or not item.strip() for item in items):
                raise CodeModeAuthorityBrokerError("provider profile summary has invalid " + field)
            if len(items) != len(set(items)):
                raise CodeModeAuthorityBrokerError("provider profile summary has duplicate " + field)
        return {
            "name": value["name"],
            "base_url": value["base_url"],
            "model": value["model"],
            "wire_protocol": value["wire_protocol"],
            "adapter_capabilities": list(value["adapter_capabilities"]),
            "allowed_endpoint_hosts": list(value["allowed_endpoint_hosts"]),
        }

    def _broker_session_for_profile(self) -> str:
        session = getattr(self, "_profile_session", None)
        if not isinstance(session, str) or not session:
            raise PermissionError("provider profile requires a bound runtime session")
        return session

    def issue_bound_canary(self, session: str, locator_request: Mapping[str, Any]) -> dict[str, Any]:
        """Request a permit from durable locators, never from caller facts.

        The authority host is the only component allowed to construct the
        signed permit.  Keeping this wire shape strict prevents a controller
        from smuggling a complete authorization body through a method that
        merely looks typed at the call site.
        """
        if not isinstance(locator_request, Mapping):
            raise PermissionError("canary issuance requires typed durable locators")
        if locator_request.get("schema") != "CODE_MODE_CANARY_LOCATOR_REQUEST_V2":
            raise PermissionError("canary issuance requires the V2 locator request")
        allowed = {
            "schema", "run_locator", "candidate_locator", "package_locator",
            "core_locator", "request_locator", "review_locator", "gate_locator",
            "live_capability_ref",
        }
        if set(locator_request) != allowed:
            raise PermissionError("canary locator request contains caller-supplied facts")
        for key in sorted(allowed - {"schema", "provider_profile", "provider_model"}):
            value = locator_request.get(key)
            if not isinstance(value, str) or not value:
                raise PermissionError("canary locator request is incomplete")
        return self._rpc({"method": "issue_canary", "session": session, "locators": dict(locator_request)})

    def register_live_capability(self, session: str, capability: Any) -> str:
        """Register only a controller-issued opaque handle.

        A serialized Mapping is deliberately not accepted here.  This is the
        narrow broker boundary where the controller-owned object identity is
        still available; the host receives its projection only after this
        type check.
        """
        from sitina.orchestrator.true_multi_agent_runtime import LiveNetworkCapabilityHandle
        if not isinstance(capability, LiveNetworkCapabilityHandle):
            raise PermissionError("live capability must be a controller-issued handle")
        projection = capability.as_mapping()
        return str(self._rpc({
            "method": "register_live_capability", "session": session,
            "capability": projection,
        }).get("capability_ref") or "")

    def issue_pre_provider_authorization(
        self, session: str, *, session_instance_id: str,
        conversation_session_id: str, turn_index: int, run_id: str,
        run_attempt: int, generation: str, provider_profile: str, provider_model: str,
    ) -> dict[str, Any]:
        """Exchange a controller-owned one-use handle for a host permit.

        The caller provides only the current scope needed to mint the
        controller handle.  The wire request contains the signed opaque
        handle projection; it has no arbitrary phase list or operation body.
        The host pins the controller public key during attestation and
        independently derives the fixed root phase allowlist.
        """
        from sitina.orchestrator.true_multi_agent_runtime import _ControllerCapabilityIssuer
        if not self.is_attested_host_client():
            raise PermissionError("pre-provider authorization requires the active host")
        handle = self._controller_capability_issuer.mint_pre_provider(
            session_instance_id=session_instance_id,
            conversation_session_id=conversation_session_id,
            turn_index=turn_index,
            run_id=run_id,
            run_attempt=run_attempt,
            generation=generation,
            provider_profile=provider_profile,
            provider_model=provider_model,
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 900,
        )
        projection = handle.as_mapping()
        authorization = self._rpc({
            "method": "issue_pre_provider_authorization",
            "session": session,
            "capability": projection,
        })
        handle.consume()
        return authorization

    def validate_bound_canary(self, session: str, authorization: Mapping[str, Any]) -> bool:
        try:
            self._rpc({"method": "validate_canary", "session": session, "authorization": dict(authorization)})
            return True
        except CodeModeAuthorityBrokerError:
            return False

    def request_acceptance_transaction(self, session: str, locators: Mapping[str, Any]) -> dict[str, Any]:
        """Request a fixed locator-only acceptance transaction.

        The client sends only the typed operation commitment.  It never gets
        a generic signer or a private key; the host adds the pinned issuer
        identity and returns the complete signed envelope.
        """
        # A broker may own more than one run-bound context over its lifetime.
        # The session supplied by the context is the binding that the host
        # verifies; a client-local "current profile session" is only a
        # convenience for profile lookup and must not invalidate another
        # still-live, host-attested run during finalization/recovery.
        if not self.is_attested_host_client():
            raise PermissionError("authority operation requires the active host session")
        if not isinstance(locators, Mapping):
            raise PermissionError("authority operation locators are invalid")
        if str(locators.get("schema") or "") != "CODE_MODE_ACCEPTANCE_LOCATOR_REQUEST_V2":
            raise PermissionError("acceptance requires durable locators")
        return self._rpc({"method": "acceptance_transaction", "session": session, "locators": dict(locators)})

    def request_completion_plan(self, session: str, locators: Mapping[str, Any]) -> dict[str, Any]:
        """Request a host-built completion plan from locator commitments.

        The worker/controller supplies only the current run-bound locator
        projection.  The authority host constructs the logical operations and
        signs the resulting plan; there is no client-facing arbitrary-body
        signer.
        """
        if not self.is_attested_host_client():
            raise PermissionError("completion-plan signing requires the active host")
        if not isinstance(locators, Mapping):
            raise PermissionError("completion plan locators are invalid")
        if str(locators.get("schema") or "") != "CODE_MODE_COMPLETION_LOCATOR_REQUEST_V2":
            raise PermissionError("completion plan requires durable locators")
        return self._rpc({"method": "request_completion_plan", "session": session, "locators": dict(locators)})

    def consume_bound_canary(self, session: str, authorization: Mapping[str, Any]) -> None:
        self._rpc({"method": "consume_canary", "session": session, "authorization": dict(authorization)})

    def _transport_bind(self, session: str, token: str, authorization: Mapping[str, Any]) -> dict[str, Any]:
        return self._rpc({"method": "transport_bind_canary", "session": session, "capability": token, "authorization": dict(authorization)})

    def _transport_bind_pre_provider(self, session: str, token: str, authorization: Mapping[str, Any]) -> dict[str, Any]:
        return self._rpc({"method": "transport_bind_pre_provider", "session": session, "capability": token, "authorization": dict(authorization)})

    def _transport_bind_forge(self, session: str, token: str, *, child_authorization_locator: str) -> dict[str, Any]:
        return self._rpc({
            "method": "transport_bind_forge", "session": session,
            "capability": token, "child_authorization_locator": child_authorization_locator,
        })

    def _transport_bind_attempt_control(self, session: str, token: str) -> dict[str, Any]:
        return self._rpc({
            "method": "transport_bind_attempt_control",
            "session": session, "capability": token,
        })

    def _transport_begin(self, session: str, token: str, authorization_id: str | None, values: Mapping[str, Any]) -> str:
        request = {"method": "transport_begin", "session": session, "capability": token, **dict(values)}
        if authorization_id is not None:
            request["authorization_id"] = authorization_id
        return str(self._rpc(request)["permit"])

    def _transport_send(self, session: str, token: str, values: Mapping[str, Any]) -> dict[str, Any]:
        return self._rpc({"method": "transport_send", "session": session, "capability": token, **dict(values)})

    def _transport_snapshot(self, session: str, token: str) -> list[Mapping[str, Any]]:
        return list(self._rpc({"method": "transport_snapshot", "session": session, "capability": token}).get("receipts", ()))

    def context_factory(
        self,
        *,
        provider: Any | None = None,
        source_root: Path | None = None,
        session_instance_id: str | None = None,
    ):
        if not self._attested:
            raise PermissionError("authority host connection is not attested")
        factory_session_instance_id = str(
            session_instance_id
            or self.identity.get("session_instance_id")
            or ("session-instance-" + secrets.token_hex(16))
        )

        def factory(home: Path):
            from sitina.orchestrator.code_mode_runtime import CodeModeRuntimeContext
            context = CodeModeRuntimeContext.open(
                home,
                provider=provider,
                source_root=source_root,
                session_instance_id=factory_session_instance_id,
            )
            root_stat = os.stat(context.home, follow_symlinks=False)
            bound = self.bind_runtime()
            self._profile_session = bound["session"]
            if dict(bound.get("binding") or {}).get("session_instance_id") != factory_session_instance_id:
                raise PermissionError("authority host session instance binding mismatch")
            context._attach_authority_broker(self, bound["session"], bound["binding"], bound["transport_capability"])
            # This proof is only a local handle to the already-attested host
            # connection.  It contains no signing material and cannot make a
            # directly opened/offline context authoritative.
            # Opaque per-context capability marker.  It is deliberately not
            # a serializable Mapping and carries no issuer material; the
            # controller session must also become the context's active
            # session before the Gate will accept it.
            context._controller_proof = object()
            context._controller_proof_issuer_id = str(self.identity.get("issuer_id") or "")
            context._controller_proof_state_identity = context.identity.state_identity
            context._controller_proof_broker_pid = int(self.identity.get("pid") or 0)
            context._controller_proof_host_code_identity = str(self.identity.get("host_code_identity") or "")
            return context
        return factory

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for stream in (getattr(self, "_reader", None), getattr(self, "_writer", None)):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
        try:
            self._channel.close()
        except OSError:
            pass
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=2)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


def _connect_attested_host(
    channel: socket.socket,
    process: subprocess.Popen[bytes],
    *,
    expected_entrypoint: Path,
    challenge: bytes,
    controller_capability_private_key: Ed25519PrivateKey | None = None,
) -> CodeModeAuthorityBroker:
    """Connect only from the fixed parent launcher attestation seam.

    This is intentionally not a class/public factory.  The CLI owns the
    process creation, bootstrap FD and challenge; this helper only verifies
    the resulting child identity before exposing the narrow client.
    """
    if not isinstance(process, subprocess.Popen) or process.poll() is not None:
        raise CodeModeAuthorityBrokerError("authority host is not a live child")
    client = CodeModeAuthorityBroker(
        channel, process, {}, controller_capability_private_key=controller_capability_private_key,
    )
    client._attested = True
    identity = client._rpc({"method": "hello"})
    try:
        public_key = bytes.fromhex(str(identity.get("authority_public_key_hex") or ""))
    except ValueError:
        public_key = b""
    if (
        int(identity.get("pid") or 0) != process.pid
        or int(identity.get("parent_pid") or 0) != os.getpid()
        or identity.get("parent_executable") != os.path.realpath(sys.executable)
        or os.path.realpath(str(identity.get("host_entrypoint") or "")) != os.path.realpath(str(expected_entrypoint))
        or identity.get("host_code_identity") != hashlib.sha256(Path(expected_entrypoint).read_bytes()).hexdigest()
        or identity.get("protocol") != "CODE_MODE_HOST_IPC_V2"
        or identity.get("trust_scope") != "same-user-cli-parent-child-v1"
        or len(public_key) != 32
        or identity.get("authority_key_id") != "host-ed25519:" + hashlib.sha256(public_key).hexdigest()
    ):
        client.close()
        raise CodeModeAuthorityBrokerError("authority host identity mismatch")
    unsigned_identity = {key: value for key, value in identity.items() if key != "challenge_proof"}
    expected_proof = hmac.new(challenge, _canonical(unsigned_identity), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(identity.get("challenge_proof") or ""), expected_proof):
        client.close()
        raise CodeModeAuthorityBrokerError("authority host challenge proof mismatch")
    client.identity = dict(identity)
    client._attested = True
    return client
