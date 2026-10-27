#!/usr/bin/env python3
"""Independent offline Reviewer verdict producer.

This process owns the verdict signing key.  The authority host later verifies
the signed result; a controller-provided Mapping, even with a matching hash
and public issuer string, is not a verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import socket
import sys
import time
import re
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


class ProducerError(PermissionError):
    pass


class ProducerService:
    def __init__(self, channel: socket.socket, bootstrap: bytes):
        if len(bootstrap) < 32:
            raise ProducerError("reviewer producer bootstrap is incomplete")
        value = json.loads(bootstrap.decode())
        challenge = value.get("challenge_secret") if isinstance(value, Mapping) else None
        if not isinstance(challenge, str):
            raise ProducerError("reviewer producer challenge is missing")
        self.challenge = bytes.fromhex(challenge)
        if len(self.challenge) < 32:
            raise ProducerError("reviewer producer challenge is incomplete")
        self.channel = channel
        self.producer_id = "code-mode-reviewer-producer-" + secrets.token_hex(12)
        self.private = Ed25519PrivateKey.generate()
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        self._used: set[str] = set()

    def sign(self, body: Mapping[str, Any]) -> dict[str, Any]:
        value = dict(body)
        value["producer_issuer_id"] = self.producer_id
        value["producer_public_key"] = self.public
        value["producer_signature"] = self.private.sign(canonical(value)).hex()
        return value

    def dispatch(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("method") == "hello":
            identity = {
                "producer_id": self.producer_id, "pid": os.getpid(), "parent_pid": os.getppid(),
                "parent_executable": os.path.realpath(sys.executable),
                "host_entrypoint": os.path.realpath(__file__),
                "host_code_identity": hashlib.sha256(open(__file__, "rb").read()).hexdigest(),
                "protocol": "CODE_MODE_REVIEWER_PRODUCER_IPC_V1",
                "public_key": self.public,
            }
            identity["challenge_proof"] = hmac.new(self.challenge, canonical(identity), hashlib.sha256).hexdigest()
            return identity
        method = request.get("method")
        if method != "review":
            raise ProducerError("reviewer producer method is not allowed")
        return self.review(request)

    def review(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """Decide a verdict from the controller-sealed objective facts.

        This is a deterministic machine review, and it says so in the verdict
        it signs: ``review_class`` is ``DETERMINISTIC_MACHINE_REVIEW_V1`` and
        ``human_confirmed`` is false, so nothing downstream can mistake this
        for a human reading the diff.  The rules below only ever read facts the
        controller already sealed and hash-bound -- return code, test counts,
        the before/after worktree hashes, and the evidence linkage.  A fact that
        is missing, malformed, or bad produces REJECT; there is no branch that
        turns an incomplete receipt into an ACCEPT.
        """
        binding = {
            key: str(request.get(key) or "")
            for key in ("candidate_id", "tree_hash", "test_receipt_hash", "run_id")
        }
        if not all(binding.values()):
            raise ProducerError("headless review requires a complete evidence binding")
        evidence = request.get("evidence")
        if not isinstance(evidence, Mapping):
            raise ProducerError("headless review requires the controller evidence projection")
        binding_key = hashlib.sha256(canonical(binding)).hexdigest()
        if binding_key in self._used:
            raise ProducerError("headless review was already issued for this binding")

        findings: list[str] = []

        def integer_fact(name: str) -> int | None:
            value = evidence.get(name)
            if isinstance(value, bool) or not isinstance(value, int):
                return None
            return value

        return_code = integer_fact("return_code")
        if return_code is None:
            findings.append("machine receipt carries no integer return_code")
        elif return_code != 0:
            findings.append(f"verification runner exited {return_code}")
        for name in ("failures", "errors", "unexpected_successes"):
            count = integer_fact(name)
            if count is None:
                findings.append(f"machine receipt carries no integer {name}")
            elif count != 0:
                findings.append(f"verification reported {count} {name}")

        before = str(evidence.get("worktree_before_hash") or "")
        after = str(evidence.get("worktree_after_hash") or "")
        if len(before) != 64 or len(after) != 64:
            findings.append("worktree before/after hashes are not both sealed digests")
        elif before != after:
            findings.append("verification mutated the worktree it was verifying")

        if len(str(evidence.get("diff_hash") or "")) != 64:
            findings.append("evidence carries no sealed diff hash")
        machine_check = str(evidence.get("machine_check_hash") or "")
        package = str(evidence.get("evidence_package_hash") or "")
        if len(machine_check) != 64 or len(package) != 64:
            findings.append("machine check and evidence package hashes are not both sealed")
        elif machine_check == package:
            findings.append("machine check is not distinct from its evidence package")
        if len(str(evidence.get("command_hash") or "")) != 64:
            findings.append("verification command is not hash-bound")

        decision = "ACCEPT" if not findings else "REJECT"
        severity = "NONE" if not findings else "HIGH"
        body = {
            "schema": "CODE_MODE_REVIEW_VERDICT_V2",
            "reviewer_session_id": self.producer_id,
            "candidate_id": binding["candidate_id"],
            "tree_hash": binding["tree_hash"],
            "test_receipt_hash": binding["test_receipt_hash"],
            "run_id": binding["run_id"],
            "review_evidence": dict(evidence),
            "review_evidence_hash": hashlib.sha256(canonical(dict(evidence))).hexdigest(),
            "findings": findings,
            "severity": severity,
            "decision": decision,
            "review_class": "DETERMINISTIC_MACHINE_REVIEW_V1",
            "human_confirmed": "false",
            "reviewed_at": str(int(time.time())),
        }
        self._used.add(binding_key)
        return {"verdict": self.sign(body)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-fd", type=int, required=True)
    parser.add_argument("--bootstrap-fd", type=int, required=True)
    args = parser.parse_args()
    with os.fdopen(args.bootstrap_fd, "rb") as handle:
        bootstrap = handle.read()
    channel = socket.socket(fileno=args.control_fd)
    service = ProducerService(channel, bootstrap)
    reader, writer = channel.makefile("rb"), channel.makefile("wb")
    try:
        for line in reader:
            try:
                value = service.dispatch(json.loads(line.decode()))
                response = {"ok": True, "value": value}
            except Exception as error:
                response = {"ok": False, "error_type": type(error).__name__, "error": str(error)[:240]}
            writer.write(canonical(response) + b"\n")
            writer.flush()
    finally:
        writer.close(); reader.close(); channel.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
