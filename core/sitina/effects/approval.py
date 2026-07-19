from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class ApprovalError(RuntimeError):
    pass


@dataclass(frozen=True)
class ApprovalBinding:
    effect_id: str
    request_hash: str
    target: str
    amount_scope: str
    policy_hash: str
    risk_class: str
    principal: str
    credential_scope: str
    adapter_operation: str
    manifest_hash: str

    def __post_init__(self) -> None:
        for value, field in (
            (self.effect_id, "effect_id"),
            (self.risk_class, "risk_class"),
            (self.principal, "principal"),
            (self.credential_scope, "credential_scope"),
            (self.adapter_operation, "adapter_operation"),
        ):
            validate_identifier(value, field=field)
        for value in (self.request_hash, self.policy_hash, self.manifest_hash):
            if len(value) != 64:
                raise ValueError("approval binding hash is invalid")
        if not self.target or not self.amount_scope:
            raise ValueError("approval target and amount/scope are required")

    @property
    def binding_hash(self) -> str:
        return domain_hash("EFFECT_APPROVAL_BINDING", canonical_json_bytes(self.__dict__))


@dataclass(frozen=True)
class EffectApproval:
    approval_id: str
    binding: ApprovalBinding
    authority: str
    expires_at: int
    allowed_attempts: int
    allowed_transport_retries: int
    used_attempt_ids: tuple[str, ...] = ()

    def authorize(
        self,
        binding: ApprovalBinding,
        *,
        effect_attempt_id: str,
        now: int,
        transport_retries: int,
    ) -> tuple["EffectApproval", dict[str, Any]]:
        validate_identifier(effect_attempt_id, field="effect_attempt_id")
        if now > self.expires_at:
            raise ApprovalError("approval expired")
        if binding.binding_hash != self.binding.binding_hash:
            raise ApprovalError("exact approval binding changed")
        if transport_retries > self.allowed_transport_retries:
            raise ApprovalError("transport retry limit exceeded")
        if effect_attempt_id in self.used_attempt_ids:
            return self, {
                "schema": "EFFECT_APPROVAL_AUTHORIZED_V1",
                "approval_id": self.approval_id,
                "effect_attempt_id": effect_attempt_id,
                "duplicate": True,
            }
        if len(self.used_attempt_ids) >= self.allowed_attempts:
            raise ApprovalError("approval attempt limit exceeded")
        updated = replace(self, used_attempt_ids=self.used_attempt_ids + (effect_attempt_id,))
        return updated, {
            "schema": "EFFECT_APPROVAL_AUTHORIZED_V1",
            "approval_id": self.approval_id,
            "binding_hash": self.binding.binding_hash,
            "effect_attempt_id": effect_attempt_id,
            "transport_retries": transport_retries,
            "duplicate": False,
        }


def issue_approval(
    approval_id: str,
    binding: ApprovalBinding,
    *,
    authority: str,
    expires_at: int,
    allowed_attempts: int,
    allowed_transport_retries: int,
) -> EffectApproval:
    validate_identifier(approval_id, field="approval_id")
    validate_identifier(authority, field="approval_authority")
    if allowed_attempts < 1 or allowed_transport_retries < 0:
        raise ApprovalError("invalid approval attempt/retry limits")
    return EffectApproval(approval_id, binding, authority, expires_at, allowed_attempts, allowed_transport_retries)


@dataclass(frozen=True)
class ApprovalWait:
    wait_id: str
    run_id: str
    effect_id: str
    binding_hash: str
    expires_at: int

    def __post_init__(self) -> None:
        for value, field in ((self.wait_id, "approval_wait_id"), (self.run_id, "run_id"), (self.effect_id, "effect_id")):
            validate_identifier(value, field=field)
        if (
            len(self.binding_hash) != 64
            or any(character not in "0123456789abcdef" for character in self.binding_hash)
            or self.expires_at < 1
        ):
            raise ApprovalError("approval wait binding or expiry is invalid")


class ApprovalWaitRegistry:
    """Event-backed pending approval projection with timeout cleanup."""

    def __init__(self, append_event: Callable[[Mapping[str, Any]], Any] | None = None):
        self._pending: dict[str, ApprovalWait] = {}
        self._append_event = append_event
        self._lock = threading.RLock()

    def _record(self, event: dict[str, Any]) -> dict[str, Any]:
        if self._append_event is not None:
            self._append_event(event)
        return event

    def begin(self, wait: ApprovalWait) -> dict[str, Any]:
        with self._lock:
            prior = self._pending.get(wait.wait_id)
            if prior is not None:
                if prior != wait:
                    raise ApprovalError("same approval wait identity has a different binding")
                return {"schema": "EFFECT_APPROVAL_WAITING_V1", **wait.__dict__, "duplicate": True}
            self._pending[wait.wait_id] = wait
            return self._record({"schema": "EFFECT_APPROVAL_WAITING_V1", **wait.__dict__, "duplicate": False})

    def authorize(
        self,
        wait_id: str,
        *,
        run_id: str,
        effect_id: str,
        binding_hash: str,
        now: int,
    ) -> dict[str, Any]:
        with self._lock:
            wait = self._pending.get(wait_id)
            if wait is None:
                raise ApprovalError("approval wait is absent or already consumed")
            if now >= wait.expires_at:
                self._pending.pop(wait_id)
                self._record({"schema": "EFFECT_APPROVAL_TIMED_OUT_V1", **wait.__dict__, "wait_state_cleaned": True})
                raise ApprovalError("approval wait timed out and was automatically denied")
            if (run_id, effect_id, binding_hash) != (wait.run_id, wait.effect_id, wait.binding_hash):
                raise ApprovalError("approval wait run/effect/hash binding changed")
            self._pending.pop(wait_id)
            return self._record(
                {
                    "schema": "EFFECT_APPROVAL_CONSUMED_V1",
                    **wait.__dict__,
                    "consumed_once": True,
                    "wait_state_cleaned": True,
                }
            )

    def expire(self, *, now: int) -> tuple[dict[str, Any], ...]:
        with self._lock:
            expired = []
            for wait_id, wait in sorted(self._pending.items()):
                if now >= wait.expires_at:
                    self._pending.pop(wait_id)
                    expired.append(
                        self._record(
                            {"schema": "EFFECT_APPROVAL_TIMED_OUT_V1", **wait.__dict__, "wait_state_cleaned": True}
                        )
                    )
            return tuple(expired)

    def pending(self) -> tuple[ApprovalWait, ...]:
        with self._lock:
            return tuple(self._pending[key] for key in sorted(self._pending))
