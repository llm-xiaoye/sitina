"""Client for the independent Code Mode offline-review authority.

The reviewer issuer lives in ``scripts/code_mode_reviewer_host.py``.  This
module intentionally contains only a narrow, attested client connection.  It
does not contain a signing key or a receipt minting primitive.  A runtime may
use a capability returned by an attested reviewer host, but it cannot choose
the reviewer identity or decision.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import subprocess
import threading
import time
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _review_evidence_from_test_receipt(test_receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Project the complete, controller-reopened evidence package.

    This is intentionally not a caller-facing verdict structure.  The
    runtime has already reopened the distinct package and verified its links;
    the independent producer receives those objective facts and decides the
    verdict without accepting a ``passed``/``decision`` field.
    """
    value = {
        "candidate_id": test_receipt.get("candidate_id"),
        "tree_hash": test_receipt.get("tree_hash"),
        "test_receipt_hash": test_receipt.get("machine_check_hash") or test_receipt.get("content_hash"),
        "evidence_package_hash": test_receipt.get("evidence_package_hash") or test_receipt.get("content_hash"),
        "run_id": test_receipt.get("run_id"),
        "session_id": test_receipt.get("session_id"),
        "generation": test_receipt.get("generation"),
        "verifier_identity": test_receipt.get("verifier_identity"),
        "command": list(test_receipt.get("command") or []),
        "command_hash": str(test_receipt.get("command_hash") or ""),
        "test_inventory": list(test_receipt.get("test_inventory") or []),
        "inventory_hash": str(test_receipt.get("inventory_hash") or ""),
        "test_ids": list(test_receipt.get("test_ids") or []),
        "interpreter": str(test_receipt.get("interpreter") or ""),
        "dependencies_hash": str(test_receipt.get("dependencies_hash") or ""),
        "cwd": str(test_receipt.get("cwd") or ""),
        "return_code": test_receipt.get("return_code"),
        "failures": test_receipt.get("failures"), "errors": test_receipt.get("errors"),
        "skipped": test_receipt.get("skipped"),
        "unexpected_successes": test_receipt.get("unexpected_successes"),
        "output_summary": dict(test_receipt.get("output_summary") or {}),
        "review_request_ref": test_receipt.get("reference_id"),
        "evidence_package_ref": test_receipt.get("evidence_package_ref"),
        "machine_check_ref": test_receipt.get("machine_check_ref"),
        "machine_check_hash": test_receipt.get("machine_check_hash"),
        "worktree_before_hash": test_receipt.get("worktree_before_hash"),
        "worktree_after_hash": test_receipt.get("worktree_after_hash"),
        "diff_hash": test_receipt.get("diff_hash"),
        "tool_ledger": dict(test_receipt.get("tool_ledger") or {}),
        "tester": dict(test_receipt.get("tester") or {}),
        "cleanup": dict(test_receipt.get("cleanup") or {}),
        "closing_root": dict(test_receipt.get("closing_root") or {}),
    }
    return value


class CodeModeReviewerAuthorityError(PermissionError):
    pass


class ReviewerReceiptCapability:
    """Opaque, one-use capability returned by one attested reviewer session."""

    __slots__ = ("_session", "_token", "_binding", "_consumed")

    def __init__(self, session: "CodeModeReviewerSession", token: str, binding: Mapping[str, Any]):
        self._session = session
        self._token = token
        self._binding = MappingProxyType(dict(binding))
        self._consumed = False


class ReviewerReviewCapability:
    """One-use pending review held by the independent producer process."""

    __slots__ = ("_producer", "_token", "_binding", "_consumed")

    def __init__(self, producer: "CodeModeReviewerProducerSession", token: str, binding: Mapping[str, Any]):
        self._producer = producer
        self._token = token
        self._binding = MappingProxyType(dict(binding))
        self._consumed = False


class ReviewerApprovalCapability:
    """One-use producer-signed verdict approval from an independent review."""

    __slots__ = ("_producer", "_token", "_binding", "_verdict", "_consumed")

    def __init__(self, producer: "CodeModeReviewerProducerSession", token: str, binding: Mapping[str, Any], verdict: Mapping[str, Any]):
        self._producer = producer
        self._token = token
        self._binding = MappingProxyType(dict(binding))
        self._verdict = MappingProxyType(dict(verdict))
        self._consumed = False


class TTYReviewConfirmation:
    """Opaque result of an actual controlling-TTY acknowledgement.

    This is deliberately not a verdict and contains no caller-selected
    decision or evidence.  The runtime sealer must re-open the durable
    request and consume its nonce before it can issue a receipt.
    """

    __slots__ = ("_session", "_request_key", "_summary_hash", "_nonce", "_expires_at", "_confirmed_at", "_proof")

    def __init__(
        self,
        session: "CodeModeReviewerSession",
        request_key: tuple[str, str],
        summary_hash: str,
        nonce: str,
        expires_at: int,
        confirmed_at: int,
        proof: Mapping[str, Any],
    ) -> None:
        self._session = session
        self._request_key = request_key
        self._summary_hash = summary_hash
        self._nonce = nonce
        self._expires_at = expires_at
        self._confirmed_at = confirmed_at
        self._proof = MappingProxyType(dict(proof))


class CodeModeReviewerProducerSession:
    """Client for the separate process that produces signed review verdicts."""

    def __init__(self, channel: socket.socket, process: subprocess.Popen[bytes], identity: Mapping[str, Any]):
        self._channel, self._process, self.identity = channel, process, dict(identity)
        self._closed = False
        self._reader = channel.makefile("rb")
        self._writer = channel.makefile("wb")
        self._lock = threading.RLock()

    @classmethod
    def connect_host(cls, channel: socket.socket, process: subprocess.Popen[bytes], *, expected_entrypoint: Path, challenge: bytes) -> "CodeModeReviewerProducerSession":
        if not isinstance(process, subprocess.Popen) or process.poll() is not None:
            raise CodeModeReviewerAuthorityError("reviewer producer is not a live child")
        client = cls(channel, process, {})
        client.identity = client._rpc({"method": "hello"})
        entrypoint = Path(expected_entrypoint).expanduser().resolve(strict=True)
        if (
            int(client.identity.get("pid") or 0) != process.pid
            or int(client.identity.get("parent_pid") or 0) != os.getpid()
            or client.identity.get("parent_executable") != os.path.realpath(os.sys.executable)
            or os.path.realpath(str(client.identity.get("host_entrypoint") or "")) != str(entrypoint)
            or client.identity.get("host_code_identity") != hashlib.sha256(entrypoint.read_bytes()).hexdigest()
            or client.identity.get("protocol") != "CODE_MODE_REVIEWER_PRODUCER_IPC_V1"
        ):
            client.close()
            raise CodeModeReviewerAuthorityError("reviewer producer identity mismatch")
        unsigned = {key: value for key, value in client.identity.items() if key != "challenge_proof"}
        expected = hmac.new(challenge, _canonical(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(client.identity.get("challenge_proof") or ""), expected):
            client.close()
            raise CodeModeReviewerAuthorityError("reviewer producer challenge proof mismatch")
        return client

    def produce_verdict(self, *, candidate_id: str, tree_hash: str, test_receipt_hash: str, run_id: str, evidence: Mapping[str, Any]) -> dict[str, Any]:
        raise CodeModeReviewerAuthorityError("reviewer requires an explicit independent review approval")

    def _review_headless(self, *, candidate_id: str, tree_hash: str, test_receipt_hash: str, run_id: str, evidence: Mapping[str, Any]) -> ReviewerApprovalCapability:
        if self._closed or not isinstance(evidence, Mapping):
            raise CodeModeReviewerAuthorityError("reviewer producer is unavailable")
        value = self._rpc({
            "method": "review", "candidate_id": candidate_id, "tree_hash": tree_hash,
            "test_receipt_hash": test_receipt_hash, "run_id": run_id,
            "evidence": dict(evidence),
        })
        verdict = value.get("verdict")
        if not isinstance(verdict, Mapping) or verdict.get("schema") != "CODE_MODE_REVIEW_VERDICT_V2":
            raise CodeModeReviewerAuthorityError("review producer did not return a signed verdict")
        binding = {
            "candidate_id": candidate_id, "tree_hash": tree_hash,
            "test_receipt_hash": test_receipt_hash, "run_id": run_id,
        }
        return ReviewerApprovalCapability(self, secrets.token_urlsafe(24), binding, verdict)

    def _rpc(self, request: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._writer.write(_canonical(dict(request)) + b"\n")
            self._writer.flush()
            line = self._reader.readline()
            if not line:
                raise CodeModeReviewerAuthorityError("reviewer producer disconnected")
            response = json.loads(line.decode("utf-8"))
            if not response.get("ok"):
                detail = str(response.get("error") or "")[:160]
                raise CodeModeReviewerAuthorityError(str(response.get("error_type") or "reviewer producer rejected request") + (": " + detail if detail else ""))
            value = response.get("value")
            if not isinstance(value, Mapping):
                raise CodeModeReviewerAuthorityError("reviewer producer response is invalid")
            return dict(value)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for stream in (self._reader, self._writer):
            try:
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


class CodeModeReviewerSession:
    """Authenticated client for one CLI-owned independent reviewer process."""

    def __init__(self, channel: socket.socket, process: subprocess.Popen[bytes], identity: Mapping[str, Any]):
        self._channel = channel
        self._process = process
        self.identity = dict(identity)
        # Direct construction is an inert client.  Only connect_host, after
        # the PID/entrypoint/challenge proof, may enable the session.
        self._attested = False
        self._closed = False
        self._lock = threading.RLock()
        self._reader = channel.makefile("rb")
        self._writer = channel.makefile("wb")
        self._capabilities: dict[str, ReviewerReceiptCapability] = {}
        self._producer_session: CodeModeReviewerProducerSession | None = None
        self._tty_verification_key: bytes | None = None

    @classmethod
    def connect_host(
        cls,
        channel: socket.socket,
        process: subprocess.Popen[bytes],
        *,
        expected_entrypoint: Path,
        challenge: bytes,
        producer_session: CodeModeReviewerProducerSession | None = None,
    ) -> "CodeModeReviewerSession":
        if not isinstance(process, subprocess.Popen) or process.poll() is not None:
            raise CodeModeReviewerAuthorityError("reviewer host is not a live child")
        client = cls(channel, process, {})
        client._attested = True  # handshake-only; cleared on any failure below
        identity = client._rpc({"method": "hello"})
        expected_entrypoint = Path(expected_entrypoint).expanduser().resolve(strict=True)
        if (
            int(identity.get("pid") or 0) != process.pid
            or int(identity.get("parent_pid") or 0) != os.getpid()
            or identity.get("parent_executable") != os.path.realpath(os.sys.executable)
            or os.path.realpath(str(identity.get("host_entrypoint") or "")) != str(expected_entrypoint)
            or identity.get("host_code_identity") != hashlib.sha256(expected_entrypoint.read_bytes()).hexdigest()
            or identity.get("protocol") != "CODE_MODE_REVIEWER_IPC_V1"
            or identity.get("authority_class") != "INDEPENDENT_REVIEWER_AUTHORITY"
        ):
            client._attested = False
            client.close()
            raise CodeModeReviewerAuthorityError("reviewer host identity mismatch")
        unsigned = {key: value for key, value in identity.items() if key != "challenge_proof"}
        expected_proof = hmac.new(challenge, _canonical(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(identity.get("challenge_proof") or ""), expected_proof):
            client._attested = False
            client.close()
            raise CodeModeReviewerAuthorityError("reviewer host challenge proof mismatch")
        client.identity = dict(identity)
        # The parent already possesses the one-session challenge used to
        # attest this reviewer host.  Keep only the derived verification key
        # for the controller launcher; it is never sent to workers or models.
        client._tty_verification_key = hashlib.sha256(
            b"sitina-code-mode-reviewer-v1\0" + challenge
        ).digest()
        if producer_session is not None:
            if not isinstance(producer_session, CodeModeReviewerProducerSession) or producer_session._closed:
                client._attested = False
                client.close()
                raise CodeModeReviewerAuthorityError("reviewer producer session is unavailable")
            client._producer_session = producer_session
        return client

    @property
    def tty_verification_material(self) -> Mapping[str, str]:
        """Launcher-only verification material for the authority host.

        This is a verifier key, not a signing API.  The reviewer process keeps
        the signing/confirmation operation; the controller host receives only
        the fixed MAC key needed to authenticate the returned proof.
        """
        if self._tty_verification_key is None or not self.is_attested_reviewer():
            raise CodeModeReviewerAuthorityError("reviewer verification material is unavailable")
        material: dict[str, str] = {
            "issuer_id": str(self.identity.get("issuer_id") or ""),
            "mac_key_hex": self._tty_verification_key.hex(),
        }
        # The authority host also uses the same launcher-pinned material to
        # verify independent reviewer receipts.  Only the producer public
        # identity crosses the boundary; its private key remains in the
        # reviewer producer process.
        producer = self._producer_session
        if producer is not None and not producer._closed:
            material.update({
                "producer_id": str(producer.identity.get("producer_id") or ""),
                "producer_public_key": str(producer.identity.get("public_key") or ""),
            })
        return MappingProxyType(material)

    def is_attested_reviewer(self) -> bool:
        return self._attested and not self._closed and self._process.poll() is None

    @property
    def independent_producer_identity(self) -> Mapping[str, Any]:
        """Public identity summary; signing keys and producer channel stay private."""
        producer = self._producer_session
        if producer is None or producer._closed:
            raise CodeModeReviewerAuthorityError("independent reviewer producer is unavailable")
        return MappingProxyType({
            "producer_id": str(producer.identity.get("producer_id") or ""),
            "public_key": str(producer.identity.get("public_key") or ""),
        })

    def _prepare_review(self, test_receipt: Mapping[str, Any]) -> ReviewerApprovalCapability:
        producer = self._producer_session
        if (
            producer is None
            or not isinstance(test_receipt, Mapping)
            or test_receipt.get("schema") != "CODE_MODE_REVIEW_REQUEST_V2"
            or not isinstance(test_receipt.get("reference_id"), str)
            or not isinstance(test_receipt.get("content_hash"), str)
        ):
            raise CodeModeReviewerAuthorityError("independent reviewer producer is unavailable")
        evidence = _review_evidence_from_test_receipt(test_receipt)
        return producer._review_headless(
            candidate_id=str(test_receipt.get("candidate_id") or ""),
            tree_hash=str(test_receipt.get("tree_hash") or ""),
            test_receipt_hash=str(test_receipt.get("machine_check_hash") or test_receipt.get("content_hash") or ""),
            run_id=str(test_receipt.get("run_id") or ""), evidence=evidence,
        )

    def confirm_tty(self, review_request: Mapping[str, Any]) -> TTYReviewConfirmation:
        """Obtain an explicit confirmation from the controlling terminal only.

        This never reads stdin, environment variables, or a worker FD.  A
        non-terminal (including a pipe) is rejected, and the confirmation is
        bound to the displayed canonical summary digest.  The returned object
        is only an acknowledgement; the controller must consume the durable
        request nonce and seal the TTY receipt.
        """
        if not self.is_attested_reviewer():
            raise CodeModeReviewerAuthorityError("TTY review requires the attested reviewer session")
        if not isinstance(review_request, Mapping) or review_request.get("schema") != "CODE_MODE_REVIEW_REQUEST_V2":
            raise CodeModeReviewerAuthorityError("TTY review requires a durable Review V2 request")
        request_key = (str(review_request.get("reference_id") or ""), str(review_request.get("content_hash") or ""))
        if not request_key[0] or not request_key[1]:
            raise CodeModeReviewerAuthorityError("TTY review request locator is incomplete")
        expires_at = review_request.get("tty_expires_at")
        nonce = review_request.get("tty_nonce")
        if type(expires_at) is not int or expires_at <= int(time.time()) or not isinstance(nonce, str) or not nonce:
            raise CodeModeReviewerAuthorityError("TTY review request is expired or has no one-use nonce")
        value = self._rpc({"method": "tty_confirm", "review_request": dict(review_request)})
        proof = value.get("proof")
        if not isinstance(proof, Mapping) or proof.get("schema") != "CODE_MODE_TTY_CONFIRMATION_V1":
            raise CodeModeReviewerAuthorityError("TTY host did not return a signed confirmation")
        digest = str(proof.get("summary_hash") or "")
        if (
            proof.get("request_ref") != request_key[0]
            or proof.get("request_hash") != request_key[1]
            or proof.get("nonce_hash") != hashlib.sha256(nonce.encode("utf-8")).hexdigest()
            or proof.get("expires_at") != expires_at
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise CodeModeReviewerAuthorityError("TTY host confirmation binding is invalid")
        return TTYReviewConfirmation(
            self, request_key, digest, nonce, expires_at,
            int(proof.get("confirmed_at") or 0), proof,
        )

    def verify_tty_confirmation(self, confirmation: TTYReviewConfirmation) -> bool:
        if not isinstance(confirmation, TTYReviewConfirmation) or confirmation._session is not self:
            return False
        if not self.is_attested_reviewer():
            return False
        try:
            result = self._rpc({"method": "verify_tty_confirmation", "proof": dict(confirmation._proof)})
            return result.get("valid") is True
        except Exception:
            return False

    def bind(
        self,
        *,
        candidate_id: str,
        tree_hash: str,
        test_receipt_hash: str,
        run_id: str,
        expires_at: int,
    ) -> ReviewerReceiptCapability:
        if not self.is_attested_reviewer():
            raise CodeModeReviewerAuthorityError("reviewer session is not attested")
        values = (candidate_id, tree_hash, test_receipt_hash, run_id)
        if not all(isinstance(value, str) and value for value in values) or expires_at <= 0:
            raise ValueError("reviewer binding is incomplete")
        value = self._rpc({
            "method": "bind", "candidate_id": candidate_id, "tree_hash": tree_hash,
            "test_receipt_hash": test_receipt_hash, "run_id": run_id, "expires_at": int(expires_at),
        })
        token = str(value.get("capability_token") or "")
        binding = value.get("binding")
        if not token or not isinstance(binding, Mapping):
            raise CodeModeReviewerAuthorityError("reviewer host returned an invalid capability")
        capability = ReviewerReceiptCapability(self, token, binding)
        self._capabilities[token] = capability
        return capability

    def issue_receipt(
        self,
        capability: ReviewerReceiptCapability,
        *,
        candidate_id: str,
        tree_hash: str,
        test_receipt_hash: str,
        run_id: str,
        test_receipt: Mapping[str, Any],
        review_approval: ReviewerApprovalCapability | None = None,
    ) -> dict[str, Any]:
        if not isinstance(capability, ReviewerReceiptCapability) or capability._session is not self:
            raise CodeModeReviewerAuthorityError("reviewer capability is not host-issued")
        if capability._consumed or self._capabilities.get(capability._token) is not capability:
            raise CodeModeReviewerAuthorityError("reviewer capability was already consumed")
        binding = capability._binding
        if any(
            str(binding.get(key) or "") != str(value)
            for key, value in (
                ("candidate_id", candidate_id), ("tree_hash", tree_hash),
                ("test_receipt_hash", test_receipt_hash), ("run_id", run_id),
            )
        ):
            raise CodeModeReviewerAuthorityError("reviewer binding does not match the requested evidence")
        producer = self._producer_session
        if producer is None or not isinstance(review_approval, ReviewerApprovalCapability) or review_approval._producer is not producer or review_approval._consumed:
            raise CodeModeReviewerAuthorityError("independent reviewer approval is required")
        if any(
            str(review_approval._binding.get(key) or "") != str(value)
            for key, value in (("candidate_id", candidate_id), ("tree_hash", tree_hash),
                               ("test_receipt_hash", test_receipt_hash), ("run_id", run_id))
        ):
            raise CodeModeReviewerAuthorityError("independent review approval binding mismatch")
        if not isinstance(test_receipt, Mapping) or test_receipt.get("content_hash") != test_receipt_hash:
            raise CodeModeReviewerAuthorityError("reviewer requires the bound test receipt")
        verdict = dict(review_approval._verdict)
        if any(verdict.get(key) != value for key, value in {
            "candidate_id": candidate_id, "tree_hash": tree_hash,
            "test_receipt_hash": test_receipt_hash, "run_id": run_id,
        }.items()):
            raise CodeModeReviewerAuthorityError("signed review verdict binding mismatch")
        result = self._rpc({
            "method": "issue", "capability_token": capability._token,
            "candidate_id": candidate_id, "tree_hash": tree_hash,
            "test_receipt_hash": test_receipt_hash, "run_id": run_id,
            "verdict": dict(verdict),
        })
        capability._consumed = True
        review_approval._consumed = True
        self._capabilities.pop(capability._token, None)
        return result

    def verify_receipt(self, receipt: Mapping[str, Any]) -> bool:
        if not self.is_attested_reviewer() or not isinstance(receipt, Mapping):
            return False
        try:
            result = self._rpc({"method": "verify", "receipt": dict(receipt)})
        except Exception:
            return False
        return result.get("valid") is True

    def _rpc(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if not self._attested or self._closed:
            raise CodeModeReviewerAuthorityError("reviewer host connection is unavailable")
        with self._lock:
            self._writer.write(_canonical(dict(request)) + b"\n")
            self._writer.flush()
            line = self._reader.readline()
            if not line:
                raise CodeModeReviewerAuthorityError("reviewer host disconnected")
            response = json.loads(line.decode("utf-8"))
            if not response.get("ok"):
                raise CodeModeReviewerAuthorityError(str(response.get("error_type") or "reviewer request rejected"))
            value = response.get("value")
            if not isinstance(value, Mapping):
                raise CodeModeReviewerAuthorityError("reviewer host response is invalid")
            return dict(value)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        producer = self._producer_session
        self._producer_session = None
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
        if producer is not None:
            producer.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
