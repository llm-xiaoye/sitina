from __future__ import annotations

import json
import unittest

from sitina.effects.approval import ApprovalBinding, ApprovalError, issue_approval
from sitina.security.secret_provider import InMemorySecretProvider, RuntimeCredentialView, SecretProviderError
from sitina.security.macos_secret_provider import MacOSSecretProvider


def binding(**changes: object) -> ApprovalBinding:
    values = {
        "effect_id": "effect-1",
        "request_hash": "a" * 64,
        "target": "mock://remote/item",
        "amount_scope": "tokens:100",
        "policy_hash": "b" * 64,
        "risk_class": "REVERSIBLE_MUTATION",
        "principal": "mock-principal",
        "credential_scope": "mock.publish",
        "adapter_operation": "mock.publish",
        "manifest_hash": "c" * 64,
    }
    values.update(changes)
    return ApprovalBinding(**values)


class EffectApprovalCredentialTests(unittest.TestCase):
    def test_every_exact_binding_dimension_invalidates_approval(self) -> None:
        approval = issue_approval("approval-1", binding(), authority="owner", expires_at=100, allowed_attempts=2, allowed_transport_retries=0)
        fields = ["request_hash", "target", "amount_scope", "policy_hash", "risk_class", "principal", "credential_scope", "adapter_operation", "manifest_hash"]
        for index, field in enumerate(fields):
            value = (str(index) * 64) if field.endswith("hash") else f"changed-{field}"
            with self.subTest(field=field), self.assertRaises(ApprovalError):
                approval.authorize(binding(**{field: value}), effect_attempt_id=f"attempt-{index}", now=1, transport_retries=0)

    def test_attempt_retry_and_expiry_limits_fail_closed(self) -> None:
        approval = issue_approval("approval-2", binding(), authority="owner", expires_at=5, allowed_attempts=1, allowed_transport_retries=0)
        approval = approval.authorize(binding(), effect_attempt_id="attempt-1", now=1, transport_retries=0)[0]
        with self.assertRaises(ApprovalError):
            approval.authorize(binding(), effect_attempt_id="attempt-2", now=2, transport_retries=0)
        with self.assertRaises(ApprovalError):
            approval.authorize(binding(), effect_attempt_id="attempt-1", now=6, transport_retries=0)
        with self.assertRaises(ApprovalError):
            issue_approval("approval-3", binding(), authority="owner", expires_at=5, allowed_attempts=1, allowed_transport_retries=0).authorize(binding(), effect_attempt_id="attempt-1", now=1, transport_retries=1)

    def test_runtime_receives_only_opaque_short_lived_minimum_scope_handle(self) -> None:
        provider = InMemorySecretProvider(now=lambda: 10)
        provider.register("mock-principal", "mock.publish", "VERY_SECRET_TOKEN")
        handle = provider.issue_handle(principal="mock-principal", scope="mock.publish", host="mock.remote", operation="mock.publish", ttl_seconds=5)
        view = RuntimeCredentialView.from_handle(handle)
        self.assertFalse(hasattr(handle, "raw_value"))
        self.assertNotIn("VERY_SECRET_TOKEN", json.dumps(view.mapping(), sort_keys=True))
        with self.assertRaises(SecretProviderError):
            provider.redeem_for_transport(handle, host="other.remote", operation="mock.publish", transport_capability=provider.transport_capability)

    def test_raw_secret_is_unavailable_to_runtime_verifier_and_sealer(self) -> None:
        provider = InMemorySecretProvider(now=lambda: 10)
        provider.register("mock-principal", "mock.publish", "VERY_SECRET_TOKEN")
        handle = provider.issue_handle(principal="mock-principal", scope="mock.publish", host="mock.remote", operation="mock.publish", ttl_seconds=5)
        for capability in (None, object()):
            with self.assertRaises(SecretProviderError):
                provider.redeem_for_transport(handle, host="mock.remote", operation="mock.publish", transport_capability=capability)

    def test_macos_provider_remains_shadow_only_in_phase4(self) -> None:
        with self.assertRaises(SecretProviderError):
            MacOSSecretProvider(now=lambda: 1, profile="production")
        self.assertEqual(MacOSSecretProvider(now=lambda: 1, profile="shadow").provider_id, "macos-secret-provider-shadow")


if __name__ == "__main__":
    unittest.main()
