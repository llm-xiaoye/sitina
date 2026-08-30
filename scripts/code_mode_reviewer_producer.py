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
        # This process has no independently supplied semantic verdict source.
        # A machine receipt, even when complete and correctly hashed, is not
        # a Reviewer decision.  Until a real headless Reviewer role is wired
        # in, production headless review is intentionally pending; callers
        # must use the controller's real /dev/tty path.
        raise ProducerError("headless semantic review is unavailable; TTY confirmation is required")


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
