from __future__ import annotations

from sitina.journal.model import canonical_json_bytes, domain_hash

from .model import AuthorityControlFacts, AuthorityResolution, AuthorityState


class AuthorityResolverError(RuntimeError):
    pass


class AuthorityResolver:
    def __init__(self, resolver_binary_hash: str, resolver_profile: str, *, ttl: int):
        if ttl < 1:
            raise ValueError("resolver TTL must be positive")
        self.resolver_binary_hash = resolver_binary_hash
        self.resolver_profile = resolver_profile
        self.ttl = ttl

    def _resolution(self, facts: AuthorityControlFacts, state: AuthorityState, reason: str, now: int) -> AuthorityResolution:
        input_hash = domain_hash("AUTHORITY_RESOLUTION_INPUT", canonical_json_bytes(facts.input_mapping()))
        core = {
            "state": state.value,
            "input_hash": input_hash,
            "input_frontier_hash": facts.input_frontier_hash,
            "resolver_binary_hash": self.resolver_binary_hash,
            "resolver_profile": self.resolver_profile,
            "issued_at": now,
            "expires_at": now + self.ttl,
            "reason": reason,
        }
        return AuthorityResolution(
            state,
            domain_hash("AUTHORITY_RESOLUTION", canonical_json_bytes(core)),
            facts.input_frontier_hash,
            input_hash,
            self.resolver_binary_hash,
            self.resolver_profile,
            now,
            now + self.ttl,
            reason,
        )

    def resolve(self, facts: AuthorityControlFacts, *, now: int) -> AuthorityResolution:
        if (
            not facts.control_stream_readable or not facts.signatures_valid or not facts.continuity_verified
            or facts.conflicting_evidence or facts.same_identity_different_hash
        ):
            return self._resolution(facts, AuthorityState.RECOVERY_REQUIRED_NO_WRITER, "CONTROL_FACTS_UNVERIFIABLE_OR_CONFLICTING", now)
        if facts.outcome_status not in {"ABSENT", "PENDING", "UNKNOWN", "COMMITTED"}:
            return self._resolution(facts, AuthorityState.RECOVERY_REQUIRED_NO_WRITER, "UNKNOWN_OUTCOME_STATUS", now)
        if facts.outcome_status == "COMMITTED":
            exact = (
                facts.prepared and facts.outcome_verified
                and facts.command_id == facts.outcome_command_id
                and facts.request_hash == facts.outcome_request_hash
                and facts.genesis_hash == facts.outcome_genesis_hash
                and facts.snapshot_hash == facts.outcome_snapshot_hash
                and all((facts.command_id, facts.request_hash, facts.genesis_hash, facts.snapshot_hash))
            )
            if exact:
                return self._resolution(facts, AuthorityState.JOURNAL_WRITER_AUTHORIZED, "EXACT_COMMITTED_CUTOVER_OUTCOME_VERIFIED", now)
            return self._resolution(facts, AuthorityState.RECOVERY_REQUIRED_NO_WRITER, "COMMITTED_OUTCOME_BINDING_INVALID", now)
        if facts.outcome_status in {"PENDING", "UNKNOWN"}:
            return self._resolution(facts, AuthorityState.CUTOVER_OUTCOME_UNKNOWN_NO_WRITER, "CUTOVER_SUBMISSION_OUTCOME_UNPROVEN", now)
        if facts.prepared:
            return self._resolution(facts, AuthorityState.CUTOVER_PREPARED_NO_WRITER, "CUTOVER_PREPARED_NOT_SUBMITTED", now)
        if facts.legacy and facts.legacy.verified and facts.cutover_absence_proven:
            return self._resolution(facts, AuthorityState.LEGACY_WRITER_AUTHORIZED, "VERIFIED_LEGACY_FACT_AND_CUTOVER_ABSENCE", now)
        return self._resolution(facts, AuthorityState.RECOVERY_REQUIRED_NO_WRITER, "NO_EXCLUSIVE_WRITER_AUTHORITY_PROOF", now)

    def resolve_cached(self, cached: AuthorityResolution, *, now: int) -> AuthorityResolution:
        if now <= cached.expires_at:
            return cached
        core = {
            "stale_resolution_id": cached.resolution_id,
            "state": AuthorityState.RECOVERY_REQUIRED_NO_WRITER.value,
            "issued_at": now,
            "expires_at": now + self.ttl,
        }
        return AuthorityResolution(
            AuthorityState.RECOVERY_REQUIRED_NO_WRITER,
            domain_hash("AUTHORITY_RESOLUTION", canonical_json_bytes(core)),
            cached.input_frontier_hash,
            cached.input_hash,
            self.resolver_binary_hash,
            self.resolver_profile,
            now,
            now + self.ttl,
            "STALE_CACHE_NO_WRITER",
        )
