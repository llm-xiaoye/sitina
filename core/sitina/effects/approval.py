from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

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
