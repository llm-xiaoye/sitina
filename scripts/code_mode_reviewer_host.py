#!/usr/bin/env python3
"""One-shot independent Code Mode offline reviewer issuer.

The controller starts this executable for a single review session.  It never
chooses a pass result or accepts a bare decision string: it consumes a
structured verdict/evidence record from the independent reviewer session,
revalidates its bindings, and signs only that result.  The client receives a
signed, one-use proof which the runtime and Gate can reopen and verify.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import select
import secrets
import socket
import stat
import sys
import time
from pathlib import Path
from typing import Any, Mapping
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ReviewerError(PermissionError):
    pass


class ReviewerService:
    def __init__(self, channel: socket.socket, bootstrap: bytes):
        if len(bootstrap) < 32:
            raise ReviewerError("reviewer bootstrap is incomplete")
        try:
            decoded = json.loads(bootstrap.decode("utf-8"))
        except Exception as error:
            raise ReviewerError("reviewer bootstrap is invalid") from error
        if not isinstance(decoded, Mapping):
            raise ReviewerError("reviewer bootstrap is invalid")
        challenge = decoded.get("challenge_secret")
        if not isinstance(challenge, str):
            raise ReviewerError("reviewer challenge is missing")
        try:
            self._challenge_secret = bytes.fromhex(challenge)
        except ValueError as error:
            raise ReviewerError("reviewer challenge is invalid") from error
        if len(self._challenge_secret) < 32:
            raise ReviewerError("reviewer challenge is incomplete")
        self.channel = channel
        self.issuer_id = "code-mode-independent-reviewer-" + secrets.token_hex(12)
        self._signing_key = hashlib.sha256(b"sitina-code-mode-reviewer-v1\0" + self._challenge_secret).digest()
        self._capabilities: dict[str, dict[str, Any]] = {}
        self._producer_id = str(decoded.get("producer_id") or "")
        self._producer_public_key = str(decoded.get("producer_public_key") or "")
        if not self._producer_id or len(self._producer_public_key) != 64:
            raise ReviewerError("independent reviewer producer pin is missing")
        try:
            self._producer_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self._producer_public_key))
        except ValueError as error:
            raise ReviewerError("independent reviewer producer key is invalid") from error

    def _mac(self, body: Mapping[str, Any]) -> str:
        return hmac.new(self._signing_key, _canonical(body), hashlib.sha256).hexdigest()

    def _signed(self, body: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(body)
        value["issuer_id"] = self.issuer_id
        value["issuer_signature"] = self._mac(value)
        return value

    def dispatch(self, request: Mapping[str, Any]) -> dict[str, Any]:
        method = request.get("method")
        if method == "hello":
            with open(__file__, "rb") as handle:
                code_identity = hashlib.sha256(handle.read()).hexdigest()
            identity = {
                "issuer_id": self.issuer_id,
                "pid": os.getpid(), "parent_pid": os.getppid(),
                "parent_executable": os.path.realpath(sys.executable),
                "host_entrypoint": os.path.realpath(__file__),
                "host_code_identity": code_identity,
                "protocol": "CODE_MODE_REVIEWER_IPC_V1",
                "authority_class": "INDEPENDENT_REVIEWER_AUTHORITY",
                "trust_scope": "same-user-cli-parent-child-v1",
            }
            identity["challenge_proof"] = hmac.new(
                self._challenge_secret,
                _canonical(identity), hashlib.sha256,
            ).hexdigest()
            return identity
        if method == "bind":
            values = tuple(request.get(key) for key in ("candidate_id", "tree_hash", "test_receipt_hash", "run_id"))
            expires_at = request.get("expires_at")
            if not all(isinstance(value, str) and value for value in values) or type(expires_at) is not int:
                raise ReviewerError("reviewer binding is incomplete")
            now = int(time.time())
            if expires_at <= now or expires_at > now + 900:
                raise ReviewerError("reviewer binding expiry is invalid")
            token = secrets.token_urlsafe(32)
            binding = {
                "candidate_id": values[0], "tree_hash": values[1],
                "test_receipt_hash": values[2], "run_id": values[3],
                "expires_at": expires_at, "issuer_id": self.issuer_id,
            }
            self._capabilities[token] = {"binding": binding, "consumed": False}
            return {"capability_token": token, "binding": binding}
        if method == "tty_confirm":
            review_request = request.get("review_request")
            if not isinstance(review_request, Mapping) or review_request.get("schema") != "CODE_MODE_REVIEW_REQUEST_V2":
                raise ReviewerError("TTY confirmation requires a Review V2 request")
            reference_id = review_request.get("reference_id")
            request_hash = review_request.get("content_hash")
            nonce = review_request.get("tty_nonce")
            expires_at = review_request.get("tty_expires_at")
            if (
                not isinstance(reference_id, str) or not reference_id.startswith("cas:")
                or not isinstance(request_hash, str) or len(request_hash) != 64
                or not isinstance(nonce, str) or not nonce
                or type(expires_at) is not int or expires_at <= int(time.time())
            ):
                raise ReviewerError("TTY confirmation request binding is incomplete")
            summary = {
                key: review_request.get(key)
                for key in ("candidate_id", "tree_hash", "run_id", "evidence_package_ref", "evidence_package_hash")
            }
            summary["nonce"] = nonce
            summary["expires_at"] = expires_at
            summary_hash = hashlib.sha256(_canonical(summary)).hexdigest()
            try:
                fd = os.open("/dev/tty", os.O_RDWR | getattr(os, "O_NOCTTY", 0))
            except OSError as error:
                raise ReviewerError("review requires an interactive controlling TTY") from error
            try:
                if not os.isatty(fd):
                    raise ReviewerError("review confirmation is not from a TTY")
                prompt = ("Code Mode review candidate=" + str(summary["candidate_id"]) +
                          " run=" + str(summary["run_id"]) + " evidence=" +
                          str(summary["evidence_package_hash"]) + " nonce=" + nonce +
                          " expires=" + str(expires_at) +
                          "; type ACCEPT " + summary_hash + " " + nonce + ": ").encode("ascii")
                os.write(fd, prompt)
                ready, _, _ = select.select([fd], [], [], 60.0)
                if not ready:
                    raise ReviewerError("TTY review confirmation timed out")
                response = os.read(fd, 512).decode("utf-8", "strict").strip()
            finally:
                os.close(fd)
            if response != "ACCEPT " + summary_hash + " " + nonce:
                raise ReviewerError("TTY review confirmation was not accepted")
            proof = {
                "schema": "CODE_MODE_TTY_CONFIRMATION_V1",
                "request_ref": reference_id,
                "request_hash": request_hash,
                "nonce_hash": hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
                "summary_hash": summary_hash,
                "issued_at": int(time.time()),
                "expires_at": expires_at,
                "confirmed_at": int(time.time()),
                "issuer_id": self.issuer_id,
            }
            proof["issuer_signature"] = self._mac(proof)
            return {"proof": proof}
        if method == "issue":
            token = request.get("capability_token")
            record = self._capabilities.get(str(token))
            if not isinstance(record, Mapping) or record.get("consumed"):
                raise ReviewerError("reviewer capability is invalid or consumed")
            binding = record.get("binding")
            if not isinstance(binding, Mapping) or int(binding.get("expires_at") or 0) <= int(time.time()):
                raise ReviewerError("reviewer capability is expired")
            for key in ("candidate_id", "tree_hash", "test_receipt_hash", "run_id"):
                if request.get(key) != binding.get(key):
                    raise ReviewerError("reviewer capability binding mismatch")
            verdict = request.get("verdict")
            if not isinstance(verdict, Mapping) or verdict.get("schema") != "CODE_MODE_REVIEW_VERDICT_V2":
                raise ReviewerError("independent reviewer verdict is required")
            verdict_fields = ("reviewer_session_id", "candidate_id", "tree_hash", "test_receipt_hash", "run_id",
                              "review_evidence_hash", "findings", "severity", "decision", "producer_issuer_id")
            if any(not isinstance(verdict.get(key), (str, list)) for key in verdict_fields):
                raise ReviewerError("reviewer verdict fields are incomplete")
            if any(verdict.get(key) != binding.get(key) for key in ("candidate_id", "tree_hash", "test_receipt_hash", "run_id")):
                raise ReviewerError("reviewer verdict binding mismatch")
            if verdict.get("reviewer_session_id") != self._producer_id or verdict.get("producer_issuer_id") != self._producer_id:
                raise ReviewerError("reviewer verdict producer is not this independent reviewer session")
            if verdict.get("producer_public_key") != self._producer_public_key:
                raise ReviewerError("reviewer verdict producer key is not the pinned producer")
            evidence = verdict.get("review_evidence")
            if not isinstance(evidence, Mapping):
                raise ReviewerError("review evidence is missing")
            expected_evidence_hash = hashlib.sha256(_canonical(dict(evidence))).hexdigest()
            if verdict.get("review_evidence_hash") != expected_evidence_hash:
                raise ReviewerError("review evidence hash mismatch")
            if verdict.get("severity") not in {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ReviewerError("review finding severity is invalid")
            if verdict.get("decision") not in {"ACCEPT", "REJECT"}:
                raise ReviewerError("review decision is invalid")
            if not isinstance(verdict.get("findings"), list):
                raise ReviewerError("review findings are invalid")
            if verdict.get("decision") == "ACCEPT" and verdict.get("severity") not in {"NONE", "LOW"}:
                raise ReviewerError("accepted review has blocking findings")
            producer_signature = verdict.get("producer_signature")
            # The producer signs its pinned public key as part of the signed
            # body; remove only the signature field before verification.
            producer_unsigned = {key: value for key, value in verdict.items() if key != "producer_signature"}
            if not isinstance(producer_signature, str):
                raise ReviewerError("reviewer verdict producer signature is missing")
            try:
                self._producer_key.verify(bytes.fromhex(producer_signature), _canonical(producer_unsigned))
            except (ValueError, InvalidSignature) as error:
                raise ReviewerError("reviewer verdict producer signature is invalid") from error
            record["consumed"] = True
            issued_at = int(time.time())
            body = {
                "schema": "CODE_MODE_REVIEW_RECEIPT_V2",
                "candidate_id": binding["candidate_id"], "tree_hash": binding["tree_hash"],
                "test_receipt_hash": binding["test_receipt_hash"], "run_id": binding["run_id"],
                "reviewer_id": self.issuer_id,
                "decision": verdict["decision"],
                "authority_class": "INDEPENDENT_REVIEWER_AUTHORITY",
                "reviewer_session_id": self.issuer_id,
                "producer_issuer_id": verdict["producer_issuer_id"],
                "producer_public_key": verdict["producer_public_key"],
                "producer_signature": verdict["producer_signature"],
                "review_evidence_hash": verdict["review_evidence_hash"],
                "findings": list(verdict["findings"]), "severity": verdict["severity"],
                "verdict_decision": verdict["decision"],
                "review_binding_hash": hashlib.sha256(_canonical(dict(binding))).hexdigest(),
                "issued_at": issued_at, "expires_at": int(binding["expires_at"]),
            }
            return self._signed(body)
        if method == "verify":
            receipt = request.get("receipt")
            if not isinstance(receipt, Mapping) or receipt.get("issuer_id") != self.issuer_id:
                return {"valid": False}
            signature = receipt.get("issuer_signature")
            # Runtime publication adds its own state identity and CAS content
            # hash after receiving this proof.  Verify the exact authority
            # projection, while the Gate separately verifies the full CAS
            # content hash.
            signed_fields = {
                "schema", "candidate_id", "tree_hash", "test_receipt_hash", "run_id",
                "reviewer_id", "decision", "authority_class", "review_binding_hash",
                "reviewer_session_id", "producer_issuer_id", "producer_public_key", "producer_signature",
                "review_evidence_hash", "findings", "severity",
                "verdict_decision", "issued_at", "expires_at", "issuer_id",
            }
            unsigned = {key: value for key, value in receipt.items() if key in signed_fields}
            return {"valid": isinstance(signature, str) and hmac.compare_digest(signature, self._mac(unsigned))}
        if method == "verify_tty_confirmation":
            proof = request.get("proof")
            if not isinstance(proof, Mapping) or proof.get("schema") != "CODE_MODE_TTY_CONFIRMATION_V1":
                return {"valid": False}
            if proof.get("issuer_id") != self.issuer_id:
                return {"valid": False}
            signature = proof.get("issuer_signature")
            unsigned = {key: value for key, value in proof.items() if key != "issuer_signature"}
            valid = isinstance(signature, str) and hmac.compare_digest(signature, self._mac(unsigned))
            valid = valid and isinstance(proof.get("request_ref"), str) and proof["request_ref"].startswith("cas:")
            valid = valid and isinstance(proof.get("request_hash"), str) and len(proof["request_hash"]) == 64
            valid = valid and isinstance(proof.get("nonce_hash"), str) and len(proof["nonce_hash"]) == 64
            valid = valid and isinstance(proof.get("summary_hash"), str) and len(proof["summary_hash"]) == 64
            valid = valid and type(proof.get("expires_at")) is int and proof["expires_at"] > int(time.time())
            return {"valid": valid}
        raise ReviewerError("reviewer method is not allowed")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-fd", type=int, required=True)
    parser.add_argument("--bootstrap-fd", type=int, required=True)
    args = parser.parse_args()
    with os.fdopen(args.bootstrap_fd, "rb", closefd=True) as handle:
        bootstrap = handle.read()
    channel = socket.socket(fileno=args.control_fd)
    service = ReviewerService(channel, bootstrap)
    reader = channel.makefile("rb")
    writer = channel.makefile("wb")
    try:
        for line in reader:
            try:
                request = json.loads(line.decode("utf-8"))
                value = service.dispatch(request)
                response = {"ok": True, "value": value}
            except Exception as error:
                response = {"ok": False, "error_type": type(error).__name__, "error": str(error)[:240]}
            writer.write(_canonical(response) + b"\n")
            writer.flush()
    finally:
        writer.close()
        reader.close()
        channel.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
