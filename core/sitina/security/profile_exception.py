from __future__ import annotations

from typing import Any, Mapping


APPROVED_PROFILE = "deepseek"
APPROVED_DIRECT_STORAGE_FINDINGS = frozenset(
    {
        "PLAINTEXT_PROVIDER_SECRET",
        "PROVIDER_SECRET_REFERENCE_MISSING",
    }
)


def evaluate_deepseek_direct_storage_exception(
    profile_audit: Mapping[str, Any],
    *,
    user_accepted: bool,
) -> dict[str, object]:
    """Evaluate the exact user-approved DeepSeek direct-storage exception.

    The exception changes acceptance classification only. It never reads,
    returns, migrates, rotates, or otherwise handles the credential value.
    Any additional profile failure or ambiguous secret source fails closed.
    """

    profiles = [dict(item) for item in profile_audit.get("profiles", [])]
    failed = [item for item in profiles if item.get("status") != "ok"]
    approved = next((item for item in profiles if item.get("profile") == APPROVED_PROFILE), None)
    other_profiles_safe = all(
        item.get("status") == "ok"
        and item.get("secret_source") == "keychain_reference"
        and item.get("secret_value_included") is False
        for item in profiles
        if item.get("profile") != APPROVED_PROFILE
    )
    exact_approved_failure = bool(
        approved is not None
        and approved.get("status") == "failed"
        and approved.get("secret_source") == "unsafe_or_missing"
        and approved.get("reference_scheme") is None
        and approved.get("reference_error") is None
        and approved.get("secret_value_included") is False
        and frozenset(str(item) for item in approved.get("findings", []))
        == APPROVED_DIRECT_STORAGE_FINDINGS
    )
    exact_failure_set = len(failed) == 1 and failed[0].get("profile") == APPROVED_PROFILE
    exact_plaintext_count = int(profile_audit.get("plaintext_secret_count", -1)) == 1
    accepted = bool(
        user_accepted
        and profiles
        and exact_approved_failure
        and exact_failure_set
        and exact_plaintext_count
        and other_profiles_safe
        and profile_audit.get("secret_values_included") is False
    )
    return {
        "schema": "SITINA_DEEPSEEK_DIRECT_STORAGE_EXCEPTION_V1",
        "status": "accepted" if accepted else "not_requested" if not user_accepted else "rejected",
        "profile": APPROVED_PROFILE,
        "decision_source": "explicit_user_direction" if user_accepted else "none",
        "accepted_risk": "direct_provider_credential_in_owner_only_profile",
        "affected_component": "profiles/deepseek.env",
        "reason": "user_approved_operational_compatibility_exception",
        "mitigation_controls": [
            "profile_file_mode_0600",
            "exact_value_scan_all_prohibited_persistence_surfaces",
            "decrypted_cas_scan",
            "redacted_cli_errors_logs_and_evidence",
            "no_credential_value_in_exception_evidence",
        ],
        "future_recommendation": "migrate_to_macos_keychain_when_the_user_revisits_the_accepted_risk",
        "raw_profile_status": str(profile_audit.get("status") or "unknown"),
        "raw_plaintext_secret_count": int(profile_audit.get("plaintext_secret_count", -1)),
        "failed_profile_count": len(failed),
        "other_profiles_reference_backed": other_profiles_safe,
        "exact_exception_shape_verified": exact_approved_failure and exact_failure_set and exact_plaintext_count,
        "credential_value_included": False,
        "credential_modified": False,
    }
