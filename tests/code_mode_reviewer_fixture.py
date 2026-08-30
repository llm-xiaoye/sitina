"""Disposable subprocess fixture for the independent Code Mode reviewer."""
from __future__ import annotations

import json
import os
import secrets
import socket
import subprocess
import sys
from pathlib import Path

from sitina.orchestrator.code_mode_reviewer import CodeModeReviewerProducerSession, CodeModeReviewerSession


def _launch_process(entrypoint: Path, bootstrap: dict) -> tuple[socket.socket, subprocess.Popen[bytes], bytes]:
    parent, child = socket.socketpair()
    bootstrap_read, bootstrap_write = os.pipe()
    challenge = secrets.token_bytes(32)
    payload = dict(bootstrap)
    payload["challenge_secret"] = challenge.hex()
    process = subprocess.Popen(
        [sys.executable, str(entrypoint), "--control-fd", str(child.fileno()), "--bootstrap-fd", str(bootstrap_read)],
        pass_fds=(child.fileno(), bootstrap_read), close_fds=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    child.close()
    os.close(bootstrap_read)
    try:
        os.write(bootstrap_write, json.dumps(payload, separators=(",", ":")).encode())
    finally:
        os.close(bootstrap_write)
    return parent, process, challenge


def launch_code_mode_reviewer() -> CodeModeReviewerSession:
    source_root = Path(__file__).resolve().parents[1]
    producer_entrypoint = source_root / "scripts" / "code_mode_reviewer_producer.py"
    producer_channel, producer_process, producer_challenge = _launch_process(producer_entrypoint, {})
    try:
        producer = CodeModeReviewerProducerSession.connect_host(
            producer_channel, producer_process, expected_entrypoint=producer_entrypoint, challenge=producer_challenge,
        )
        host_entrypoint = source_root / "scripts" / "code_mode_reviewer_host.py"
        host_channel, host_process, host_challenge = _launch_process(
            host_entrypoint, {
                "producer_id": producer.identity["producer_id"],
                "producer_public_key": producer.identity["public_key"],
            },
        )
        try:
            reviewer = CodeModeReviewerSession.connect_host(
                host_channel, host_process, expected_entrypoint=host_entrypoint, challenge=host_challenge,
                producer_session=producer,
            )
        except Exception:
            producer.close()
            raise
        return reviewer
    except Exception:
        try:
            producer_channel.close()
        except OSError:
            pass
        if producer_process.poll() is None:
            producer_process.kill()
            producer_process.wait(timeout=2)
        raise
