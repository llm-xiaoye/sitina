"""Safety-equivalence layer for the winner->bridge execution path (method 2).

Migrates the handoff invariants that execution actually needs into a single,
deterministic, dependency-injected orchestrator so they are enforced regardless
of whether Atlas emitted a "handoff" protocol:

  H4  boundary redaction  -> boundary_check on the deliverable/diff, fail-closed
                             BEFORE it crosses the persistence boundary
  H11 executor independence -> executor_id != verifier_id, asserted
  H12 independent verify  -> verifier inspects the ACTUAL diff/tests/workspace
  H6  bounded rework      -> max_attempts, failed attempts isolated, fail-closed

The bridge return value is a formal ExecutionResult; the caller must only
terminalize as SUCCEEDED when result.accepted is True.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping, Sequence


class ExecutionBridgeError(RuntimeError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,255}$")
_TRUSTED_EXECUTOR_ID = "forge-execution-role"
_TRUSTED_EXECUTOR_ROLE = "forge-isolated-workspace-executor-v1"
_PROPOSER_CAPABILITY = "proposal"
_VERIFIER_CAPABILITY = "verification"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _authority_ref(resolution_id: str, frontier_hash: str) -> str:
    return "authority-resolution:" + _sha256(
        {
            "schema": "SITINA_EXECUTION_AUTHORITY_REF_V1",
            "resolution_id": resolution_id,
            "input_frontier_hash": frontier_hash,
        }
    )


def _registry_identity_ref(
    *,
    registry_hash: str,
    agent_id: str,
    role: str,
    required_capability: str,
    identity_hash: str,
) -> str:
    return "agent-registry-identity:" + _sha256(
        {
            "schema": "SITINA_EXECUTION_REGISTRY_IDENTITY_REF_V1",
            "registry_hash": registry_hash,
            "agent_id": agent_id,
            "role": role,
            "required_capability": required_capability,
            "identity_hash": identity_hash,
        }
    )


def _executor_role_authorization_ref(
    *,
    registry_hash: str,
    policy_hash: str,
    executor_id: str,
    executor_role: str,
) -> str:
    return "execution-role-authorization:" + _sha256(
        {
            "schema": "SITINA_EXECUTION_ROLE_AUTHORIZATION_V1",
            "registry_hash": registry_hash,
            "policy_hash": policy_hash,
            "executor_id": executor_id,
            "executor_role": executor_role,
            "permissions": [
                "isolated-workspace-write",
                "no-external-mutation",
                "no-network",
                "no-shell",
            ],
        }
    )


@dataclass(frozen=True)
class ExecutionIdentityBinding:
    """Registry-, policy-, role- and authority-bound execution principals."""

    proposer_id: str
    proposer_role: str
    proposer_capability: str
    proposer_identity_hash: str
    proposer_registry_ref: str
    executor_id: str
    executor_role: str
    executor_role_authorization_ref: str
    verifier_id: str
    verifier_role: str
    verifier_capability: str
    verifier_identity_hash: str
    verifier_registry_ref: str
    registry_hash: str
    policy_hash: str
    authority_resolution_id: str
    authority_input_frontier_hash: str
    authority_ref: str

    def __post_init__(self) -> None:
        identities = (self.proposer_id, self.executor_id, self.verifier_id)
        if any(not _IDENTIFIER.fullmatch(value) for value in identities):
            raise ValueError("execution identities must be non-empty valid identifiers")
        if len(set(identities)) != 3:
            raise ValueError("execution requires three distinct principals")
        if (
            self.proposer_capability != _PROPOSER_CAPABILITY
            or self.verifier_capability != _VERIFIER_CAPABILITY
        ):
            raise ValueError("execution principal capabilities are not trusted")
        if (
            self.executor_id != _TRUSTED_EXECUTOR_ID
            or self.executor_role != _TRUSTED_EXECUTOR_ROLE
        ):
            raise ValueError("execution role is not trusted")
        for value in (
            self.proposer_identity_hash,
            self.verifier_identity_hash,
            self.registry_hash,
            self.policy_hash,
            self.authority_resolution_id,
            self.authority_input_frontier_hash,
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError("execution identity binding requires exact SHA-256 identities")
        if not self.proposer_role or not self.verifier_role:
            raise ValueError("execution registry roles must be non-empty")
        if self.proposer_registry_ref != _registry_identity_ref(
            registry_hash=self.registry_hash,
            agent_id=self.proposer_id,
            role=self.proposer_role,
            required_capability=self.proposer_capability,
            identity_hash=self.proposer_identity_hash,
        ):
            raise ValueError("execution proposer registry binding is invalid")
        if self.verifier_registry_ref != _registry_identity_ref(
            registry_hash=self.registry_hash,
            agent_id=self.verifier_id,
            role=self.verifier_role,
            required_capability=self.verifier_capability,
            identity_hash=self.verifier_identity_hash,
        ):
            raise ValueError("execution verifier registry binding is invalid")
        if self.executor_role_authorization_ref != _executor_role_authorization_ref(
            registry_hash=self.registry_hash,
            policy_hash=self.policy_hash,
            executor_id=self.executor_id,
            executor_role=self.executor_role,
        ):
            raise ValueError("execution role authorization binding is invalid")
        if self.authority_ref != _authority_ref(
            self.authority_resolution_id, self.authority_input_frontier_hash
        ):
            raise ValueError("execution authority binding is invalid")

    @classmethod
    def from_registry(
        cls,
        registry: object,
        *,
        policy_hash: str,
        authority_resolution: object,
        proposer_id: str,
        executor_id: str,
        verifier_id: str,
        now: int,
    ) -> "ExecutionIdentityBinding":
        from sitina.authority.model import AuthorityResolution
        from sitina.orchestrator.true_multi_agent_runtime import AgentRegistry

        if type(registry) is not AgentRegistry:
            raise ExecutionBridgeError("execution requires an authentic AgentRegistry")
        if type(authority_resolution) is not AuthorityResolution:
            raise ExecutionBridgeError("execution requires an authentic AuthorityResolution")
        try:
            authority_resolution.assert_fresh(now=now)
        except Exception as error:
            raise ExecutionBridgeError("execution authority is stale") from error
        if not authority_resolution.authorizes_journal or authority_resolution.writer_count != 1:
            raise ExecutionBridgeError("execution requires one Journal writer authority")
        if not _SHA256.fullmatch(policy_hash):
            raise ExecutionBridgeError("execution policy hash is invalid")
        expected_registry_hash = _sha256(
            {
                "schema": "SITINA_TRUE_MULTI_AGENT_REGISTRY_V1",
                "generation": registry.generation,
                "agents": [identity.mapping() for identity in registry.identities],
            }
        )
        if registry.registry_hash != expected_registry_hash:
            raise ExecutionBridgeError("execution AgentRegistry hash is invalid")
        try:
            proposer = registry.get(proposer_id)
            verifier = registry.get(verifier_id)
        except Exception as error:
            raise ExecutionBridgeError("execution principal is absent from the registry") from error
        if _PROPOSER_CAPABILITY not in proposer.capabilities:
            raise ExecutionBridgeError("execution proposer lacks proposal capability")
        if _VERIFIER_CAPABILITY not in verifier.capabilities:
            raise ExecutionBridgeError("execution verifier lacks verification capability")
        for identity, label in ((proposer, "proposer"), (verifier, "verifier")):
            if not {"read-only", "provider-text-only"}.issubset(identity.safety_classes):
                raise ExecutionBridgeError(f"execution {label} role is not trusted")
        if executor_id != _TRUSTED_EXECUTOR_ID:
            raise ExecutionBridgeError("execution executor lacks explicit role authorization")
        proposer_identity_hash = _sha256(proposer.mapping())
        verifier_identity_hash = _sha256(verifier.mapping())
        resolution_id = str(authority_resolution.resolution_id)
        frontier_hash = str(authority_resolution.input_frontier_hash)
        registry_hash = str(registry.registry_hash)
        return cls(
            proposer_id=proposer.agent_id,
            proposer_role=proposer.role,
            proposer_capability=_PROPOSER_CAPABILITY,
            proposer_identity_hash=proposer_identity_hash,
            proposer_registry_ref=_registry_identity_ref(
                registry_hash=registry_hash,
                agent_id=proposer.agent_id,
                role=proposer.role,
                required_capability=_PROPOSER_CAPABILITY,
                identity_hash=proposer_identity_hash,
            ),
            executor_id=executor_id,
            executor_role=_TRUSTED_EXECUTOR_ROLE,
            executor_role_authorization_ref=_executor_role_authorization_ref(
                registry_hash=registry_hash,
                policy_hash=policy_hash,
                executor_id=executor_id,
                executor_role=_TRUSTED_EXECUTOR_ROLE,
            ),
            verifier_id=verifier.agent_id,
            verifier_role=verifier.role,
            verifier_capability=_VERIFIER_CAPABILITY,
            verifier_identity_hash=verifier_identity_hash,
            verifier_registry_ref=_registry_identity_ref(
                registry_hash=registry_hash,
                agent_id=verifier.agent_id,
                role=verifier.role,
                required_capability=_VERIFIER_CAPABILITY,
                identity_hash=verifier_identity_hash,
            ),
            registry_hash=registry_hash,
            policy_hash=policy_hash,
            authority_resolution_id=resolution_id,
            authority_input_frontier_hash=frontier_hash,
            authority_ref=_authority_ref(resolution_id, frontier_hash),
        )

    @classmethod
    def fixture(
        cls,
        *,
        proposer_id: str = "fixture-proposer",
        executor_id: str = _TRUSTED_EXECUTOR_ID,
        verifier_id: str = "fixture-verifier",
        policy_hash: str | None = None,
        registry_hash: str | None = None,
        authority_resolution_id: str | None = None,
        authority_input_frontier_hash: str | None = None,
    ) -> "ExecutionIdentityBinding":
        registry_hash = registry_hash or hashlib.sha256(
            b"sitina-execution-fixture-registry-v1"
        ).hexdigest()
        policy_hash = policy_hash or hashlib.sha256(
            b"sitina-execution-fixture-policy-v1"
        ).hexdigest()
        resolution_id = authority_resolution_id or hashlib.sha256(
            b"sitina-execution-fixture-authority-v1"
        ).hexdigest()
        frontier_hash = authority_input_frontier_hash or hashlib.sha256(
            b"sitina-execution-fixture-frontier-v1"
        ).hexdigest()
        if any(
            not _SHA256.fullmatch(value)
            for value in (registry_hash, policy_hash, resolution_id, frontier_hash)
        ):
            raise ValueError("fixture execution binding hash is invalid")
        proposer_role = "fixture-proposer"
        verifier_role = "fixture-verifier"
        proposer_identity_hash = _sha256(
            {
                "agent_id": proposer_id,
                "role": proposer_role,
                "capabilities": [_PROPOSER_CAPABILITY],
            }
        )
        verifier_identity_hash = _sha256(
            {
                "agent_id": verifier_id,
                "role": verifier_role,
                "capabilities": [_VERIFIER_CAPABILITY],
            }
        )
        return cls(
            proposer_id,
            proposer_role,
            _PROPOSER_CAPABILITY,
            proposer_identity_hash,
            _registry_identity_ref(
                registry_hash=registry_hash,
                agent_id=proposer_id,
                role=proposer_role,
                required_capability=_PROPOSER_CAPABILITY,
                identity_hash=proposer_identity_hash,
            ),
            executor_id,
            _TRUSTED_EXECUTOR_ROLE,
            _executor_role_authorization_ref(
                registry_hash=registry_hash,
                policy_hash=policy_hash,
                executor_id=executor_id,
                executor_role=_TRUSTED_EXECUTOR_ROLE,
            ),
            verifier_id,
            verifier_role,
            _VERIFIER_CAPABILITY,
            verifier_identity_hash,
            _registry_identity_ref(
                registry_hash=registry_hash,
                agent_id=verifier_id,
                role=verifier_role,
                required_capability=_VERIFIER_CAPABILITY,
                identity_hash=verifier_identity_hash,
            ),
            registry_hash,
            policy_hash,
            resolution_id,
            frontier_hash,
            _authority_ref(resolution_id, frontier_hash),
        )

    def assert_current(
        self,
        registry: object,
        *,
        policy_hash: str,
        authority_resolution: object,
        now: int,
    ) -> None:
        current = type(self).from_registry(
            registry,
            policy_hash=policy_hash,
            authority_resolution=authority_resolution,
            proposer_id=self.proposer_id,
            executor_id=self.executor_id,
            verifier_id=self.verifier_id,
            now=now,
        )
        if current != self:
            raise ExecutionBridgeError("execution identity binding is stale or altered")

    def mapping(self) -> dict[str, str]:
        return {
            "schema": "SITINA_EXECUTION_IDENTITY_BINDING_V1",
            "proposer_id": self.proposer_id,
            "proposer_role": self.proposer_role,
            "proposer_capability": self.proposer_capability,
            "proposer_identity_hash": self.proposer_identity_hash,
            "proposer_registry_ref": self.proposer_registry_ref,
            "executor_id": self.executor_id,
            "executor_role": self.executor_role,
            "executor_role_authorization_ref": self.executor_role_authorization_ref,
            "verifier_id": self.verifier_id,
            "verifier_role": self.verifier_role,
            "verifier_capability": self.verifier_capability,
            "verifier_identity_hash": self.verifier_identity_hash,
            "verifier_registry_ref": self.verifier_registry_ref,
            "registry_hash": self.registry_hash,
            "policy_hash": self.policy_hash,
            "authority_resolution_id": self.authority_resolution_id,
            "authority_input_frontier_hash": self.authority_input_frontier_hash,
            "authority_ref": self.authority_ref,
        }

    @property
    def binding_hash(self) -> str:
        return _sha256(self.mapping())


@dataclass(frozen=True)
class ExecutionBinding:
    """Immutable identity every execution attempt is bound to (Req 5)."""

    winner_output_hash: str
    approved_scope: tuple[str, ...]
    policy_hash: str
    run_id: str
    identity: ExecutionIdentityBinding

    def __post_init__(self) -> None:
        for name, value in (
            ("winner_output_hash", self.winner_output_hash),
            ("policy_hash", self.policy_hash),
        ):
            if not re.fullmatch(r"[0-9a-f]{64}", value):
                raise ValueError(f"{name} must be an exact SHA-256 hash")
        if not self.run_id or not self.approved_scope:
            raise ValueError("execution binding requires run_id and approved_scope")
        if any(not isinstance(value, str) or not value.strip() for value in self.approved_scope):
            raise ValueError("execution approved_scope entries must be non-empty paths")
        if self.identity.policy_hash != self.policy_hash:
            raise ValueError("execution binding policy differs from identity authorization")


@dataclass(frozen=True)
class VerificationVerdict:
    """Result of an INDEPENDENT verifier inspecting the real diff (Req 6)."""

    accepted: bool
    verifier_id: str
    checked_diff: bool
    checked_tests: bool
    identity: ExecutionIdentityBinding
    reasons: tuple[str, ...] = ()
    test_evidence_ref: str | None = None
    test_evidence_hash: str | None = None

    def __post_init__(self) -> None:
        if self.verifier_id != self.identity.verifier_id:
            raise ValueError("verification verdict identity differs from verifier")
        if self.test_evidence_hash is not None and not _SHA256.fullmatch(
            self.test_evidence_hash
        ):
            raise ValueError("verification verdict evidence hash is invalid")

    def mapping(self) -> dict[str, object]:
        return {
            "schema": "SITINA_EXECUTION_VERDICT_V2",
            "accepted": self.accepted,
            "verifier_id": self.verifier_id,
            "checked_diff": self.checked_diff,
            "checked_tests": self.checked_tests,
            "reasons": list(self.reasons),
            "test_evidence_ref": self.test_evidence_ref,
            "test_evidence_hash": self.test_evidence_hash,
            "execution_identity": self.identity.mapping(),
            "execution_identity_hash": self.identity.binding_hash,
        }

    @property
    def verdict_hash(self) -> str:
        return _sha256(self.mapping())


@dataclass(frozen=True)
class ExecutionResult:
    """Formal, non-discardable bridge result (Req 4). terminalize as SUCCEEDED
    only when accepted is True."""

    status: str  # "accepted" | "rejected" | "blocked" | "failed"
    accepted: bool
    binding: ExecutionBinding
    attempts: int
    workspace: str
    diff_paths: tuple[str, ...] = ()
    verification: VerificationVerdict | None = None
    redaction_ok: bool = False
    notes: tuple[str, ...] = ()
    patch_manifest_ref: str | None = None
    patch_manifest_hash: str | None = None
    attempt_ledger: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if type(self.binding) is not ExecutionBinding:
            raise ValueError("execution result binding is invalid")
        if (
            self.verification is not None
            and self.verification.identity != self.binding.identity
        ):
            raise ValueError("execution result verifier identity differs from binding")

    @property
    def execution_attempt_id(self) -> str:
        raw = _canonical(
            {
                "run_id": self.binding.run_id,
                "attempt": self.attempts,
                "workspace": self.workspace,
                "diff_paths": list(self.diff_paths),
                "execution_identity_hash": self.binding.identity.binding_hash,
            }
        )
        return "execution-attempt:" + hashlib.sha256(raw).hexdigest()

    @property
    def result_id(self) -> str:
        raw = _canonical(
            {
                "execution_attempt_id": self.execution_attempt_id,
                "status": self.status,
                "accepted": self.accepted,
                "patch_manifest_hash": self.patch_manifest_hash,
                "test_evidence_hash": self.verification.test_evidence_hash
                if self.verification
                else None,
                "verification_verdict_hash": self.verification.verdict_hash
                if self.verification
                else None,
                "attempt_ledger": [dict(item) for item in self.attempt_ledger],
                "execution_identity_hash": self.binding.identity.binding_hash,
            }
        )
        return "execution-result:" + hashlib.sha256(raw).hexdigest()

    def _event_core(self) -> dict[str, Any]:
        return {
            "schema": "FORGE_EXECUTION_RESULT_V2",
            "status": self.status,
            "accepted": self.accepted,
            "winner_output_hash": self.binding.winner_output_hash,
            "approved_scope": list(self.binding.approved_scope),
            "policy_hash": self.binding.policy_hash,
            "run_id": self.binding.run_id,
            "execution_attempt_id": self.execution_attempt_id,
            "result_id": self.result_id,
            "attempts": self.attempts,
            "workspace": self.workspace,
            "diff_paths": list(self.diff_paths),
            "redaction_ok": self.redaction_ok,
            "verifier_id": self.verification.verifier_id if self.verification else None,
            "verification_accepted": self.verification.accepted if self.verification else None,
            "verification_verdict_hash": self.verification.verdict_hash
            if self.verification
            else None,
            "test_evidence_ref": self.verification.test_evidence_ref if self.verification else None,
            "test_evidence_hash": self.verification.test_evidence_hash if self.verification else None,
            "patch_manifest_ref": self.patch_manifest_ref,
            "patch_manifest_hash": self.patch_manifest_hash,
            "execution_identity": self.binding.identity.mapping(),
            "execution_identity_hash": self.binding.identity.binding_hash,
            "notes": list(self.notes),
            "attempt_ledger": [dict(item) for item in self.attempt_ledger],
        }

    @property
    def event_hash(self) -> str:
        return _sha256(self._event_core())

    def as_event(self) -> dict[str, Any]:
        return {**self._event_core(), "event_hash": self.event_hash}

def run_safe_execution(
    *,
    binding: ExecutionBinding,
    executor_id: str,
    workspace: str,
    forge_runner: Callable[[int, str], Mapping[str, Any]],
    collect_diff: Callable[[], Sequence[str]],
    boundary_check: Callable[[Sequence[str]], Sequence[str]],
    verifier: Callable[[Sequence[str], Mapping[str, Any]], VerificationVerdict],
    rollback: Callable[[int], None],
    max_attempts: int = 2,
    replan: Callable[[int, Mapping[str, Any]], Mapping[str, Any]] | None = None,
) -> ExecutionResult:
    """Deterministic safe-execution orchestrator. All effects are injected so
    this is fully unit-testable without a provider.

    forge_runner(attempt, workspace) -> runtime result mapping (the Forge loop).
    collect_diff() -> the ACTUAL changed paths in the workspace.
    boundary_check(diff_paths) -> list of redacted/sensitive paths (empty == ok).
    verifier(diff_paths, forge_result) -> VerificationVerdict (independent).
    rollback(attempt) -> undo/isolate a rejected attempt's workspace changes.
    """
    if max_attempts < 1:
        raise ExecutionBridgeError("max_attempts must be >= 1")
    if executor_id != binding.identity.executor_id:
        raise ExecutionBridgeError("executor differs from the authorized execution role")
    workspace_path = Path(workspace).expanduser().resolve(strict=False)
    approved_roots = tuple(
        (
            Path(value).expanduser()
            if Path(value).expanduser().is_absolute()
            else workspace_path / Path(value).expanduser()
        ).resolve(strict=False)
        for value in binding.approved_scope
    )

    def _approved(path_value: str) -> bool:
        candidate = Path(path_value).expanduser()
        if not candidate.is_absolute():
            candidate = workspace_path / candidate
        candidate = candidate.resolve(strict=False)
        return any(candidate == root or root in candidate.parents for root in approved_roots)

    notes: list[str] = []
    last_diff: tuple[str, ...] = ()
    attempt_ledger: list[dict[str, Any]] = []
    last_failure: dict[str, Any] | None = None

    def _make_result(**kwargs: Any) -> ExecutionResult:
        return ExecutionResult(
            **kwargs,
            attempt_ledger=tuple(dict(item) for item in attempt_ledger),
        )

    def _record_failure(
        attempt: int,
        *,
        plan_hash: str,
        failure_type: str,
        failure_hash: str,
        replan_result: Mapping[str, Any],
        stage: str,
        forge_bound: bool | None = None,
        attempt_binding: Mapping[str, Any] | None = None,
    ) -> None:
        """Append the immutable per-attempt failure record.

        The ledger is the source of truth for rework decisions.  In
        particular, callers must not infer a repeated failure from an
        incidental note string: the consecutive type/hash signature is
        recorded explicitly and is what the execution event consumes.
        """
        previous = last_failure
        same_failure = bool(
            previous
            and str(previous.get("failure_type") or "") == failure_type
            and str(previous.get("failure_hash") or "") == failure_hash
        )
        binding_facts = dict(attempt_binding) if isinstance(attempt_binding, Mapping) else {}
        attempt_ledger.append(
            {
                "attempt": attempt,
                "plan_hash": plan_hash,
                "result": "FAILED",
                "stage": stage,
                "forge_bound": bool(stage != "Forge" if forge_bound is None else forge_bound),
                "failure_type": failure_type,
                "failure_hash": failure_hash,
                "prior_failure_type": str(previous.get("failure_type")) if previous else None,
                "prior_failure_hash": str(previous.get("failure_hash")) if previous else None,
                "same_failure": same_failure,
                "replan": bool(replan_result),
                "rollback": "pending",
                "authorization_ref": binding_facts.get("authorization_ref"),
                "child_run_id": binding_facts.get("child_run_id"),
                "receipt_cursor": binding_facts.get("receipt_cursor"),
            }
        )
        last_failure_update = {
            "failure_type": failure_type,
            "failure_hash": failure_hash,
            "plan_hash": plan_hash,
        }
        # Python closures cannot rebind a local without nonlocal.  Mutate a
        # stable holder instead so every later stage sees the latest signature.
        failure_holder[0] = last_failure_update

    failure_holder: list[dict[str, Any] | None] = [None]

    def _rollback_or_fail(attempt: int) -> str | None:
        try:
            rollback(attempt)
            if attempt_ledger and attempt_ledger[-1].get("attempt") == attempt:
                attempt_ledger[-1]["rollback"] = "ok"
            return None
        except Exception as error:
            # A rollback failure is an external safety failure, not a reason
            # to continue another Forge attempt.  Preserve only typed identity
            # and a hash; callers must terminalize FAILED, never ACCEPTED.
            error_hash = hashlib.sha256(str(error).encode("utf-8")).hexdigest()
            notes.append(f"attempt{attempt}:rollback_failed:{type(error).__name__}:{error_hash}")
            if attempt_ledger and attempt_ledger[-1].get("attempt") == attempt:
                attempt_ledger[-1]["rollback"] = "failed"
                attempt_ledger[-1]["rollback_failure_type"] = type(error).__name__
                attempt_ledger[-1]["rollback_failure_hash"] = error_hash
            return error_hash

    for attempt in range(1, max_attempts + 1):
        # Rework always receives the prior typed failure.  The resulting plan
        # hash is stored on this attempt; it is never an unbound blind retry.
        last_failure = failure_holder[0]
        replan_result: Mapping[str, Any] = {}
        if attempt > 1 and last_failure is not None and replan is not None:
            previous_attempt = attempt_ledger[-1] if attempt_ledger else {}
            if previous_attempt.get("forge_bound") is not True:
                error_hash = hashlib.sha256(b"replan-before-forge-binding").hexdigest()
                attempt_ledger.append({
                    "attempt": attempt, "plan_hash": str(last_failure.get("plan_hash") or binding.winner_output_hash),
                    "result": "FAILED", "failure_type": "ReplanAdmissionError", "failure_hash": error_hash,
                    "stage": "Planner", "forge_bound": False, "replan": False,
                    "same_failure": False, "rollback": "not_started",
                })
                notes.append(f"attempt{attempt}:replan_rejected_before_forge_binding:{error_hash}")
                return _make_result(
                    status="failed", accepted=False, binding=binding, attempts=attempt,
                    workspace=workspace, notes=tuple(notes),
                )
            try:
                replan_result = dict(replan(attempt, dict(last_failure)))
                notes.append(
                    f"attempt{attempt}:replanned:{replan_result.get('plan_hash') or 'unhashed'}"
                )
            except Exception as error:
                error_hash = hashlib.sha256(str(error).encode("utf-8")).hexdigest()
                attempt_ledger.append(
                    {
                        "attempt": attempt,
                        "plan_hash": str(last_failure.get("plan_hash") or binding.winner_output_hash),
                        "result": "FAILED",
                        "failure_type": type(error).__name__,
                        "failure_hash": error_hash,
                        "stage": "Planner",
                        "replan": False,
                        "same_failure": False,
                        "rollback": "not_started",
                    }
                )
                notes.append(f"attempt{attempt}:replan_failed:{type(error).__name__}:{error_hash}")
                return _make_result(
                    status="failed", accepted=False, binding=binding, attempts=attempt,
                    workspace=workspace, redaction_ok=False, notes=tuple(notes),
                )
        plan_hash = str(replan_result.get("plan_hash") or binding.winner_output_hash)
        try:
            forge_result = forge_runner(attempt, workspace)
            # Bind the verifier/sandbox child to the actual bounded attempt;
            # this is metadata supplied by the controller, never a model
            # assertion.
            forge_result = dict(forge_result)
            forge_result.setdefault("attempt", attempt)
        except Exception as error:
            error_hash = hashlib.sha256(str(error).encode("utf-8")).hexdigest()
            forge_result = {
                "terminal_state": "FAILED",
                "attempt": attempt,
                "error_type": type(error).__name__,
                "error_hash": error_hash,
                "secret_values_included": False,
                # A thrown runner exception represents an execution attempt
                # that reached the runner boundary.  Production callers that
                # fail before child binding return an explicit mapping with
                # forge_bound=False, so this compatibility path cannot turn
                # an admission rejection into a blind replan.
                "forge_bound": True,
            }
        # If the Forge loop itself failed/hit its guards, isolate and retry.
        if str(forge_result.get("terminal_state")) != "SUCCEEDED":
            failure_hash = str(forge_result.get("error_hash") or "")
            failure_type = str(forge_result.get("error_type") or "ForgeFailure")
            suffix = f":{failure_hash}" if failure_hash else ""
            notes.append(f"attempt{attempt}:forge_not_succeeded:{forge_result.get('terminal_state')}{suffix}")
            failure_hash = failure_hash or hashlib.sha256(failure_type.encode("utf-8")).hexdigest()
            _record_failure(
                attempt, plan_hash=plan_hash, failure_type=failure_type,
                failure_hash=failure_hash, replan_result=replan_result, stage="Forge",
                forge_bound=bool(forge_result.get("forge_bound")),
                attempt_binding=forge_result.get("attempt_binding"),
            )
            if _rollback_or_fail(attempt) is not None:
                return _make_result(
                    status="failed", accepted=False, binding=binding, attempts=attempt,
                    workspace=workspace, redaction_ok=False, notes=tuple(notes),
                )
            continue

        try:
            diff_paths = tuple(str(value) for value in collect_diff())
        except Exception as error:
            error_hash = hashlib.sha256(str(error).encode("utf-8")).hexdigest()
            notes.append(f"attempt{attempt}:diff_collection_failed:{type(error).__name__}:{error_hash}")
            _record_failure(
                attempt, plan_hash=plan_hash, failure_type="DiffCollectionError",
                failure_hash=error_hash, replan_result=replan_result, stage="Tester",
            )
            if _rollback_or_fail(attempt) is not None:
                return _make_result(
                    status="failed", accepted=False, binding=binding, attempts=attempt,
                    workspace=workspace, redaction_ok=False, notes=tuple(notes),
                )
            continue
        last_diff = diff_paths

        if not diff_paths or len(set(diff_paths)) != len(diff_paths) or any(
            not _approved(value) for value in diff_paths
        ):
            notes.append(f"attempt{attempt}:scope_blocked")
            scope_hash = hashlib.sha256(",".join(sorted(diff_paths)).encode("utf-8")).hexdigest()
            _record_failure(
                attempt, plan_hash=plan_hash, failure_type="ScopeBlocked",
                failure_hash=scope_hash, replan_result=replan_result, stage="Boundary",
            )
            if _rollback_or_fail(attempt) is not None:
                return _make_result(
                    status="failed", accepted=False, binding=binding, attempts=attempt,
                    workspace=workspace, diff_paths=diff_paths, redaction_ok=False,
                    notes=tuple(notes),
                )
            return _make_result(
                status="blocked", accepted=False, binding=binding, attempts=attempt,
                workspace=workspace, diff_paths=diff_paths, redaction_ok=False,
                notes=tuple(notes),
            )

        # H4: sensitive-content hard gate on the deliverable/diff BEFORE accept.
        # SL1 already blocks per-write; this is the deliverable-level boundary.
        try:
            sensitive = tuple(boundary_check(diff_paths))
        except Exception as error:
            error_hash = hashlib.sha256(str(error).encode("utf-8")).hexdigest()
            notes.append(f"attempt{attempt}:boundary_check_failed:{type(error).__name__}:{error_hash}")
            _record_failure(
                attempt, plan_hash=plan_hash, failure_type="BoundaryCheckError",
                failure_hash=error_hash, replan_result=replan_result, stage="Tester",
            )
            if _rollback_or_fail(attempt) is not None:
                return _make_result(
                    status="failed", accepted=False, binding=binding, attempts=attempt,
                    workspace=workspace, diff_paths=diff_paths, redaction_ok=False,
                    notes=tuple(notes),
                )
            continue
        if sensitive:
            notes.append(f"attempt{attempt}:boundary_blocked:{','.join(sensitive)}")
            sensitive_hash = hashlib.sha256(",".join(sorted(sensitive)).encode("utf-8")).hexdigest()
            _record_failure(
                attempt, plan_hash=plan_hash, failure_type="SensitiveBoundaryBlocked",
                failure_hash=sensitive_hash, replan_result=replan_result, stage="Boundary",
            )
            if _rollback_or_fail(attempt) is not None:
                return _make_result(
                    status="failed", accepted=False, binding=binding, attempts=attempt,
                    workspace=workspace, diff_paths=diff_paths, redaction_ok=False,
                    notes=tuple(notes),
                )
            # sensitive content is not a "try again differently" condition;
            # fail-closed immediately rather than loop.
            return _make_result(
                status="blocked", accepted=False, binding=binding, attempts=attempt,
                workspace=workspace, diff_paths=diff_paths, redaction_ok=False,
                notes=tuple(notes),
            )

        # H11: executor must not be its own verifier.
        try:
            verdict = verifier(diff_paths, forge_result)
        except Exception as error:
            error_hash = hashlib.sha256(str(error).encode("utf-8")).hexdigest()
            notes.append(f"attempt{attempt}:tester_failed:{type(error).__name__}:{error_hash}")
            _record_failure(
                attempt, plan_hash=plan_hash, failure_type="TesterExecutionError",
                failure_hash=error_hash, replan_result=replan_result, stage="Tester",
            )
            if _rollback_or_fail(attempt) is not None:
                return _make_result(
                    status="failed", accepted=False, binding=binding, attempts=attempt,
                    workspace=workspace, diff_paths=diff_paths, redaction_ok=False,
                    notes=tuple(notes),
                )
            continue
        try:
            if verdict.identity != binding.identity:
                raise ExecutionBridgeError("verdict execution identity binding differs")
            if verdict.verifier_id == executor_id:
                raise ExecutionBridgeError(
                    f"executor and verifier must differ (both {executor_id})"
                )
            # H12: verifier must have actually inspected the diff (not text self-report).
            if not verdict.checked_diff:
                raise ExecutionBridgeError("verifier did not inspect the actual diff")
        except Exception as error:
            error_hash = hashlib.sha256(str(error).encode("utf-8")).hexdigest()
            notes.append(f"attempt{attempt}:tester_failed:{type(error).__name__}:{error_hash}")
            _record_failure(
                attempt, plan_hash=plan_hash, failure_type="TesterBindingError",
                failure_hash=error_hash, replan_result=replan_result, stage="Tester",
            )
            if _rollback_or_fail(attempt) is not None:
                return _make_result(
                    status="failed", accepted=False, binding=binding, attempts=attempt,
                    workspace=workspace, diff_paths=diff_paths, redaction_ok=False,
                    notes=tuple(notes),
                )
            continue
        # H12 (test evidence): an ACCEPT is only valid with real executed-test
        # evidence. Syntax-only ("checked_tests=False") must never be accepted —
        # that was the hollow-acceptance bug. Fail-closed: downgrade to reject.
        evidence_bound = (
            isinstance(verdict.test_evidence_ref, str)
            and bool(re.fullmatch(r"(?:cas|test-evidence):[0-9a-f]{64}", verdict.test_evidence_ref))
            and isinstance(verdict.test_evidence_hash, str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", verdict.test_evidence_hash))
        )
        if (
            evidence_bound
            and verdict.test_evidence_ref is not None
            and verdict.test_evidence_ref.startswith("test-evidence:")
            and verdict.test_evidence_ref.removeprefix("test-evidence:")
            != verdict.test_evidence_hash
        ):
            evidence_bound = False
        if verdict.accepted and (not verdict.checked_tests or not evidence_bound):
            notes.append(f"attempt{attempt}:rejected:accept_without_test_evidence")
            failure_hash = hashlib.sha256(b"accept_without_test_evidence").hexdigest()
            _record_failure(
                attempt, plan_hash=plan_hash, failure_type="TesterEvidenceMissing",
                failure_hash=failure_hash, replan_result=replan_result, stage="Tester",
            )
            if _rollback_or_fail(attempt) is not None:
                return _make_result(
                    status="failed", accepted=False, binding=binding, attempts=attempt,
                    workspace=workspace, diff_paths=diff_paths, redaction_ok=False,
                    notes=tuple(notes),
                )
            continue

        if verdict.accepted:
            attempt_ledger.append(
                {
                    "attempt": attempt,
                    "plan_hash": plan_hash,
                    "result": "ACCEPTED",
                    "failure_type": None,
                    "failure_hash": None,
                    "prior_failure_type": str(last_failure.get("failure_type")) if last_failure else None,
                    "prior_failure_hash": str(last_failure.get("failure_hash")) if last_failure else None,
                    "same_failure": False,
                    "replan": bool(replan_result),
                    "rollback": "not_required",
                    "forge_bound": True,
                    "authorization_ref": (
                        forge_result.get("attempt_binding", {}).get("authorization_ref")
                        if isinstance(forge_result.get("attempt_binding"), Mapping) else None
                    ),
                    "child_run_id": (
                        forge_result.get("attempt_binding", {}).get("child_run_id")
                        if isinstance(forge_result.get("attempt_binding"), Mapping) else None
                    ),
                    "receipt_cursor": (
                        forge_result.get("attempt_binding", {}).get("receipt_cursor")
                        if isinstance(forge_result.get("attempt_binding"), Mapping) else None
                    ),
                }
            )
            notes.append(f"attempt{attempt}:accepted")
            return _make_result(
                status="accepted", accepted=True, binding=binding, attempts=attempt,
                workspace=workspace, diff_paths=diff_paths, verification=verdict,
                redaction_ok=True, notes=tuple(notes),
            )

        # H6: rejected -> isolate this attempt and rework (bounded).
        notes.append(f"attempt{attempt}:rejected:{';'.join(verdict.reasons) or 'no-reason'}")
        failure_hash = verdict.verdict_hash
        reviewer_rejected = "post_execution_reviewer_rejected" in verdict.reasons
        _record_failure(
            attempt,
            plan_hash=plan_hash,
            failure_type=("PostExecutionReviewerRejected" if reviewer_rejected else "TesterRejected"),
            failure_hash=failure_hash,
            replan_result=replan_result,
            stage=("Reviewer" if reviewer_rejected else "Tester"),
        )
        if _rollback_or_fail(attempt) is not None:
            return _make_result(
                status="failed", accepted=False, binding=binding, attempts=attempt,
                workspace=workspace, diff_paths=diff_paths, redaction_ok=False,
                notes=tuple(notes),
            )

    # Bounded rework exhausted -> fail-closed.
    return _make_result(
        status="rejected", accepted=False, binding=binding, attempts=max_attempts,
        workspace=workspace, diff_paths=last_diff, redaction_ok=True,
        notes=tuple(notes) + ("rework_exhausted_fail_closed",),
    )
