from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sitina.journal.model import canonical_json_bytes


class EffectRecoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class EffectIdentity:
    session_id: str
    turn_index: int
    message_id: str
    logical_call_id: str
    provider_profile: str
    request_hash: str
    effect_id: str

    @classmethod
    def build(
        cls,
        *,
        session_id: str,
        turn_index: int,
        message_id: str,
        logical_call_id: str,
        provider_profile: str,
        request_hash: str,
    ) -> "EffectIdentity":
        value = {
            "session_id": session_id,
            "turn_index": turn_index,
            "message_id": message_id,
            "logical_call_id": logical_call_id,
            "provider_profile": provider_profile,
            "request_hash": request_hash,
        }
        if turn_index < 0 or len(request_hash) != 64 or any(not value[key] for key in value if key != "turn_index"):
            raise EffectRecoveryError("invalid Provider effect identity")
        effect_id = "effect-" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()
        return cls(session_id, turn_index, message_id, logical_call_id, provider_profile, request_hash, effect_id)

    def mapping(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "turn_index": self.turn_index,
            "message_id": self.message_id,
            "logical_call_id": self.logical_call_id,
            "provider_profile": self.provider_profile,
            "request_hash": self.request_hash,
            "effect_id": self.effect_id,
        }


@dataclass(frozen=True)
class EffectRecord:
    identity: EffectIdentity
    state: str
    fencing_token: int
    result_ref: str | None = None
    committed_position: int | None = None


class DurableProviderEffect:
    STATES = {
        "NOT_SENT",
        "SEND_STARTED",
        "SENT_OUTCOME_UNKNOWN",
        "RESULT_CAS_PUBLISHED",
        "RESULT_JOURNAL_COMMITTED",
    }

    def __init__(self, home: str | Path):
        self.home = Path(home).resolve(strict=True)
        self.root = self.home / "runtime" / "provider-effects"
        self.root.mkdir(parents=True, exist_ok=True)
        self._mutex = threading.RLock()

    def _path(self, effect_id: str) -> Path:
        return self.root / (hashlib.sha256(effect_id.encode()).hexdigest() + ".json")

    def _write(self, record: EffectRecord) -> None:
        value = {
            "schema": "SITINA_DURABLE_PROVIDER_EFFECT_V1",
            "identity": record.identity.mapping(),
            "state": record.state,
            "fencing_token": record.fencing_token,
            "result_ref": record.result_ref,
            "committed_position": record.committed_position,
        }
        path = self._path(record.identity.effect_id)
        temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, canonical_json_bytes(value) + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        directory = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def load(self, effect_id: str) -> EffectRecord:
        path = self._path(effect_id)
        if not path.is_file() or path.is_symlink():
            raise EffectRecoveryError("Provider effect receipt is missing")
        value = json.loads(path.read_text(encoding="utf-8"))
        identity = EffectIdentity(**value["identity"])
        return EffectRecord(identity, value["state"], value["fencing_token"], value.get("result_ref"), value.get("committed_position"))

    def request(self, identity: EffectIdentity) -> EffectRecord:
        with self._mutex:
            try:
                current = self.load(identity.effect_id)
            except EffectRecoveryError:
                current = EffectRecord(identity, "NOT_SENT", 0)
                self._write(current)
            if current.identity != identity:
                raise EffectRecoveryError("effect identity collision")
            return current

    def begin_send(self, effect_id: str, *, fencing_token: int) -> EffectRecord:
        with self._mutex:
            current = self.load(effect_id)
            if current.state != "NOT_SENT":
                raise EffectRecoveryError("effect is not proven NOT_SENT; physical resend denied")
            if fencing_token <= current.fencing_token:
                raise EffectRecoveryError("effect fencing token is stale")
            value = EffectRecord(current.identity, "SEND_STARTED", fencing_token)
            self._write(value)
            return value

    def _advance(
        self,
        effect_id: str,
        *,
        fencing_token: int,
        allowed: tuple[str, ...],
        state: str,
        result_ref: str | None = None,
        committed_position: int | None = None,
    ) -> EffectRecord:
        with self._mutex:
            current = self.load(effect_id)
            if current.fencing_token != fencing_token:
                raise EffectRecoveryError("effect fencing token is stale")
            if current.state == state:
                return current
            if current.state not in allowed:
                raise EffectRecoveryError(f"invalid Provider effect transition: {current.state} -> {state}")
            value = EffectRecord(
                current.identity,
                state,
                fencing_token,
                result_ref if result_ref is not None else current.result_ref,
                committed_position if committed_position is not None else current.committed_position,
            )
            self._write(value)
            return value

    def mark_outcome_unknown(self, effect_id: str, *, fencing_token: int) -> EffectRecord:
        return self._advance(effect_id, fencing_token=fencing_token, allowed=("SEND_STARTED",), state="SENT_OUTCOME_UNKNOWN")

    def record_result_cas_published(self, effect_id: str, *, fencing_token: int, result_ref: str) -> EffectRecord:
        if not result_ref.startswith("cas:"):
            raise EffectRecoveryError("Provider result must be a CAS reference")
        return self._advance(
            effect_id,
            fencing_token=fencing_token,
            allowed=("SEND_STARTED", "SENT_OUTCOME_UNKNOWN"),
            state="RESULT_CAS_PUBLISHED",
            result_ref=result_ref,
        )

    def record_result_journal_committed(self, effect_id: str, *, fencing_token: int, position: int) -> EffectRecord:
        return self._advance(
            effect_id,
            fencing_token=fencing_token,
            allowed=("RESULT_CAS_PUBLISHED",),
            state="RESULT_JOURNAL_COMMITTED",
            committed_position=position,
        )

    def may_physically_send(self, effect_id: str) -> bool:
        return self.load(effect_id).state == "NOT_SENT"
