from __future__ import annotations

import json
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.orchestrator.timeout_support import ProviderTimeoutConfig, RunCancelledError, RunControlStore, RunDeadline, TimeoutError
from sitina.reliability import RetrySchedule, RetryScheduler, RetrySettings
from sitina.runners.agent_parser import AgentOutputParser, AgentParseError
from sitina.runners.prompt_contracts import PromptContractRegistry
from sitina.runners.provider import (
    AnthropicCompatibleClient,
    ProviderAuthError,
    ProviderCompletion,
    ProviderConnectTimeout,
    ProviderDeadlineExceeded,
    ProviderError,
    ProviderMalformedResponse,
    ProviderPermissionError,
    ProviderRateLimitError,
    ProviderReadTimeout,
    RoleProfileResolver,
    provider_identity_summary,
)
from sitina.schemas.models import CommonAgentOutput, validate_agent_input
from sitina.storage import SitinaStore
from sitina.utils import canonicalize_agent_input, compute_agent_input_hash, ensure_dir, iso_now, new_id, redact_text, sha256_text, stable_json, write_json


class AgentRunnerError(RuntimeError):
    def __init__(self, message: str, *, error_type: str = "agent_runner_failed", details: dict[str, Any] | None = None):
        super().__init__(message)
        self.error_type = error_type
        self.details = details or {}


@dataclass(frozen=True)
class AgentRunResult:
    agent: str
    output: CommonAgentOutput
    payload: dict[str, Any]
    raw_text: str
    provider_mode: str
    profile_name: str | None
    model: str | None
    provider_identity: dict[str, Any]
    repair_attempts: int
    provider_calls: list[dict[str, Any]]
    fallback_used: bool = False
    logical_call_id: str | None = None


class MockProvider:
    def __init__(self, home: Path):
        self.home = Path(home).resolve()

    def complete(self, agent: str, input_payload: dict[str, Any]) -> str:
        factory = getattr(self, f"_{agent}", None)
        if not factory:
            raise ProviderError(f"mock provider has no output for {agent}")
        return json.dumps(factory(input_payload), ensure_ascii=False, sort_keys=True)

    def _controller(self, payload: dict[str, Any]) -> dict[str, Any]:
        goal = str(payload.get("user_goal", "")).lower()
        risk_level = payload.get("risk_scan_result", {}).get("risk_level", "low")
        if "high-risk-code-fixture" in goal or "high-risk-full-gate-fixture" in goal:
            return self._base("controller", "next_agent", verification_status="not_verified") | {
                "next_agent": "planner",
                "mandatory_steps_ack": True,
                "task_type": "high_risk_code_change",
                "need_planner": True,
                "need_coder": True,
                "need_filesystem": False,
                "need_tester": True,
                "need_reviewer": True,
                "risk_level": "high",
                "requested_tools": [],
                "target_paths": [],
                "next_agents": ["planner"],
                "blocked_reason": None,
            }
        if "approved write fixture" in goal or "approved-write-fixture" in goal:
            return self._base("controller", "next_agent", verification_status="not_verified") | {
                "next_agent": "planner",
                "mandatory_steps_ack": True,
                "task_type": "code_change",
                "need_planner": True,
                "need_coder": True,
                "need_filesystem": False,
                "need_tester": True,
                "need_reviewer": True,
                "risk_level": risk_level if risk_level in {"low", "medium", "high", "critical"} else "low",
                "requested_tools": [],
                "target_paths": [str(self.home / "outputs/generated/approved_write_fixture.txt")],
                "next_agents": ["planner"],
                "blocked_reason": None,
            }
        if (
            "retry-rework-fixture" in goal
            or "multi-reviewer-rework-fixture" in goal
            or "proposal-competition-fixture" in goal
            or "arbitration-block-fixture" in goal
            or "arbitration-ask-user-fixture" in goal
            or "lease-arbitration-fixture" in goal
            or "lease-arbitration-block-fixture" in goal
            or "lease-conflict-block-fixture" in goal
            or "handoff-reject-fixture" in goal
            or "invalid-handoff-decision-fixture" in goal
            or "side-effect-descriptor-fixture" in goal
        ):
            return self._base("controller", "next_agent", verification_status="not_verified") | {
                "next_agent": "planner",
                "mandatory_steps_ack": True,
                "task_type": "code_change",
                "need_planner": True,
                "need_coder": True,
                "need_filesystem": False,
                "need_tester": True,
                "need_reviewer": True,
                "risk_level": "low",
                "requested_tools": [],
                "target_paths": [],
                "next_agents": ["planner"],
                "blocked_reason": None,
            }
        if "code-change-fixture" in goal:
            return self._base("controller", "next_agent", verification_status="not_verified") | {
                "next_agent": "planner",
                "mandatory_steps_ack": True,
                "task_type": "code_change",
                "need_planner": True,
                "need_coder": True,
                "need_filesystem": False,
                "need_tester": True,
                "need_reviewer": True,
                "risk_level": "low",
                "requested_tools": [],
                "target_paths": [],
                "next_agents": ["planner"],
                "blocked_reason": None,
            }
        if "maintenance-fixture" in goal:
            return self._base("controller", "summarize", verification_status="not_verified") | {
                "next_agent": "summary",
                "mandatory_steps_ack": True,
                "task_type": "maintenance",
                "need_planner": False,
                "need_coder": False,
                "need_filesystem": False,
                "need_tester": False,
                "need_reviewer": True,
                "risk_level": "high",
                "requested_tools": ["maintenance_guarded"],
                "target_paths": [],
                "next_agents": ["summary"],
                "blocked_reason": None,
            }
        if "local-file-query-fixture" in goal or "filesystem query fixture" in goal:
            return self._base("controller", "summarize", verification_status="partially_verified") | {
                "next_agent": "summary",
                "mandatory_steps_ack": True,
                "task_type": "local_file_query",
                "need_planner": False,
                "need_coder": False,
                "need_filesystem": True,
                "need_tester": False,
                "need_reviewer": False,
                "risk_level": "low",
                "requested_tools": ["filesystem:list_dir"],
                "target_paths": [str(self.home)],
                "next_agents": ["summary"],
                "blocked_reason": None,
            }
        return self._base("controller", "summarize", verification_status="partially_verified") | {
            "next_agent": "summary",
            "mandatory_steps_ack": True,
            "task_type": "chat",
            "need_planner": False,
            "need_coder": False,
            "need_filesystem": False,
            "need_tester": False,
            "need_reviewer": False,
            "risk_level": "low",
            "requested_tools": [],
            "target_paths": [],
            "next_agents": ["summary"],
            "blocked_reason": None,
        }

    def _planner(self, payload: dict[str, Any]) -> dict[str, Any]:
        goal = payload.get("user_goal", "").lower()
        if payload.get("project_context", {}).get("handoff_decision_request"):
            if "invalid-handoff-decision-fixture" in goal:
                handoff_decision = {"decision": "maybe", "reason": ""}
            elif "handoff-reject-fixture" in goal:
                handoff_decision = {
                    "decision": "reject",
                    "reason": "handoff-reject-fixture receiver agent rejected planner handoff",
                    "required_gates": ["scope_conflict_arbitration"],
                    "confidence": 0.93,
                    "notes": ["Mock planner refused the receiver handoff through structured output."],
                    "safety_issues": ["receiver_rejected_scope"],
                }
            else:
                handoff_decision = {
                    "decision": "accept",
                    "reason": "planner receiver agent accepted task graph dispatch",
                    "required_gates": [],
                    "confidence": 0.88,
                    "notes": ["Mock planner accepted the handoff contract."],
                    "safety_issues": [],
                }
            return self._base("planner", "plan", verification_status="verified") | {
                "plan_steps": ["Evaluate handoff contract", "Return structured receiver decision"],
                "acceptance_criteria": ["handoff decision is schema-valid", "fail closed on reject or invalid"],
                "proposed_touched_files": [],
                "risk_assessment": {"risk_level": "low", "approval_required": False, "provider_mode": "mock"},
                "confidence": 0.9,
                "assumptions": ["The supplied handoff contract is the complete decision scope."],
                "unknowns": [],
                "alternatives": ["Reject the handoff when contract evidence proves a conflict."],
                "extensions": {"handoff_decision": handoff_decision},
            }
        if "approved write fixture" in goal or "approved-write-fixture" in goal:
            target = str(self.home / "outputs/generated/approved_write_fixture.txt")
            touched = [target]
            steps = ["Request approval for the fixture file", "Write the approved fixture content", "Verify artifact and reviewer gates"]
            acceptance = ["approved fixture file exists", "file content matches approved coder output", "reviewer accepts with no blockers"]
        else:
            touched = []
            steps = ["Validate Sitina harness configuration", "Run tester artifact binding", "Review deterministic output"]
            acceptance = ["config validate passes", "tester artifact belongs to current run", "reviewer accepts with no blockers"]
        project_context = payload.get("project_context") if isinstance(payload.get("project_context"), dict) else {}
        minimal_contract = project_context.get("minimal_live_contract") if isinstance(project_context.get("minimal_live_contract"), dict) else {}
        return self._base("planner", "plan", verification_status="partially_verified") | {
            "plan_steps": steps,
            "acceptance_criteria": acceptance,
            "proposed_touched_files": touched,
            "risk_assessment": {"risk_level": "low", "approval_required": False, "provider_mode": "mock"},
            "confidence": 0.74,
            "assumptions": ["No mutation may occur before scoped approval."],
            "unknowns": [],
            "alternatives": ["Use a read-only validation path when no mutation is requested."],
            "extensions": {
                "proposal_bid": {
                    "summary": "Planner proposes the policy-compiled task graph with mandatory gates preserved.",
                    "proposal_type": "task_graph",
                    **(
                        {
                            "task_graph_patch": {
                                "strategy": "controlled_noop_policy_graph",
                                "controlled_noop_policy_graph": True,
                                "real_side_effects_forbidden": True,
                            }
                        }
                        if minimal_contract
                        else {}
                    ),
                    "estimated_steps": max(3, len(steps)),
                    "estimated_risk": "low",
                    "required_gates": ["tester", "reviewer", "memory_check"],
                    "read_paths": list(minimal_contract.get("read_paths") or []),
                    "write_paths": [],
                    "writable_scope": [],
                    "touched_files": touched,
                    "required_side_effects": [],
                    "assumptions": ["No mutation may occur before scoped approval."],
                    "confidence": 0.74,
                    "rollback_plan": ["No direct mutation in proposal phase.", "Use approved rollback if coder writes later."],
                    "verification_plan": ["Run tester gate.", "Require reviewer gate.", "Run replay diff."],
                    "expected_artifacts": ["task_graph", "run_ledger"],
                    "safety_notes": ["proposal enters policy compiler instead of executing directly"],
                }
            },
        }

    def _tester(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._base("tester", "pass", verification_status="verified") | {
            "tests_run": ["sitina config validate"],
            "acceptance_results": [{"criterion": "config validate passes", "passed": True}],
            "artifact_hash": payload.get("expected_artifact_hash"),
            "resolved_findings": [],
            "environment": {"provider_mode": "mock"},
            "risk_level": "low",
            "test_types": ["contract"],
            "reproducibility": ["Run sitina config validate in the isolated test home."],
            "evidence_complete": True,
            "extensions": {
                "proposal_bid": {
                    "summary": "Tester proposes a verification-first path with tester and reviewer gates.",
                    "proposal_type": "test_strategy",
                    "estimated_steps": 2,
                    "estimated_risk": "low",
                    "required_gates": ["tester", "reviewer", "memory_check"],
                    "required_side_effects": [],
                    "assumptions": ["Verification can run without write access."],
                    "confidence": 0.68,
                    "rollback_plan": ["No rollback needed before mutation."],
                    "verification_plan": ["Bind command artifact.", "Verify acceptance criteria."],
                    "expected_artifacts": ["test_artifact"],
                },
                "proposal_evaluation": {"decision": "support", "score": 78, "reason": "Verification plan is executable in current harness."},
            },
        }

    def _reviewer(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._base("reviewer", "accept", verification_status="verified") | {
            "findings": [],
            "resolved_findings": [],
            "overall_recommendation": "accept",
            "original_requirement_assessment": [],
            "extensions": {
                "proposal_bid": {
                    "summary": "Reviewer proposes preserving review as the final code gate.",
                    "proposal_type": "review_strategy",
                    "estimated_steps": 3,
                    "estimated_risk": "low",
                    "required_gates": ["tester", "reviewer", "memory_check"],
                    "required_side_effects": [],
                    "assumptions": ["Reviewer remains independent from proposer."],
                    "confidence": 0.66,
                    "rollback_plan": ["Block success if review finds major or critical issues."],
                    "verification_plan": ["Require tester evidence.", "Review mandatory artifacts."],
                    "expected_artifacts": ["review_decision"],
                },
                "proposal_evaluation": {"decision": "support", "score": 84, "reason": "Proposal preserves reviewer gate."},
            },
        }

    def _summary(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._base("summary", "summary", verification_status="verified") | {
            "user_summary": "Mock provider workflow completed with schema-validated agent outputs.",
            "verification_status_derived": "verified",
            "unverified_items": [],
            "goal": "Complete the supplied mock workflow.",
            "completed": ["Schema-validated agent outputs were produced."],
            "decisions": ["Use the deterministic mock provider."],
            "constraints": ["No external provider call was made."],
            "failures": [],
            "open_items": [],
            "evidence_summary": ["mock-provider-output"],
        }

    def _coder(self, payload: dict[str, Any]) -> dict[str, Any]:
        files = payload.get("approved_touched_files", [])
        before_hashes = payload.get("before_hashes", {})
        writes = [
            {
                "path": path,
                "before_hash": before_hashes.get(path),
                "content": "Sitina approved write fixture.\nThis file was written only after scoped approval.\n",
            }
            for path in files
        ]
        return self._base("coder", "unchanged", verification_status="not_verified") | {
            "input_scope_hash": payload["input_scope_hash"],
            "files_touched": files,
            "patch_id": "patch_noop",
            "scope_compliance": "in_scope",
            "extensions": {"file_writes": writes},
        }

    def _architect(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._base("architect", "architecture_plan", verification_status="partially_verified") | {
            "architecture_decisions": ["No high-risk architecture change required in mock mode"],
            "rollback_plan": ["No file changes produced"],
            "boundary_notes": ["Mock mode does not execute writes"],
            "extensions": {
                "proposal_bid": {
                    "summary": "Architect proposes a guarded architecture path with explicit rollback and review gates.",
                    "proposal_type": "task_graph",
                    "estimated_steps": 5,
                    "estimated_risk": "high",
                    "required_gates": ["tester", "multi_reviewer_merge", "approval", "patch_hash_verify", "patch_apply", "memory_check"],
                    "required_side_effects": [],
                    "assumptions": ["High-risk work remains in managed worktree until approval."],
                    "confidence": 0.72,
                    "rollback_plan": ["Use generated patch and worktree rollback artifacts."],
                    "verification_plan": ["Multi-reviewer merge.", "Patch hash verification.", "Replay simulate."],
                    "expected_artifacts": ["worktree", "patch", "review_merge"],
                    "task_graph_patch": {"strategy": "high_risk_worktree_policy_graph"},
                },
                "proposal_evaluation": {"decision": "support", "score": 81, "reason": "Architecture proposal keeps rollback and gate boundaries explicit."},
            },
        }

    def _critic(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._base("critic", "no_objection", verification_status="partially_verified") | {
            "objections": [],
            "counterexamples": [],
            "extensions": {"proposal_evaluation": {"decision": "support", "score": 82, "reason": "No hidden unsafe assumption found in mock evaluation."}},
        }

    def _researcher(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._base("researcher", "evidence", verification_status="partially_verified") | {
            "sources_checked": ["local_context"],
            "untrusted_blocks": [],
            "facts": [],
            "inferences": [],
            "unknowns": [],
            "source_freshness": {"local_context": "current_run"},
            "extensions": {
                "proposal_bid": {
                    "summary": "Researcher proposes readonly evidence gathering with local citations.",
                    "proposal_type": "task_graph",
                    "estimated_steps": 2,
                    "estimated_risk": "low",
                    "required_gates": ["filesystem_readonly", "summary", "memory_check"],
                    "required_side_effects": [],
                    "assumptions": ["Readonly source access is sufficient."],
                    "confidence": 0.7,
                    "rollback_plan": ["No mutation allowed."],
                    "verification_plan": ["Cite local evidence.", "Summarize readonly results."],
                    "expected_artifacts": ["evidence"],
                },
                "proposal_evaluation": {"decision": "support", "score": 86, "reason": "Readonly evidence path is appropriate."},
            },
        }

    def _security(self, payload: dict[str, Any]) -> dict[str, Any]:
        proposal = payload.get("current_plan", {}).get("proposal", {})
        text = json.dumps(proposal, ensure_ascii=False, sort_keys=True).lower()
        unsafe = any(marker in text for marker in ("patch_apply", "bypass_reviewer", "approval_mutation", "memory_accept", "write_file"))
        decision = "block" if unsafe else "support"
        severity = "critical" if unsafe else "none"
        return self._base("security", decision, verification_status="verified" if not unsafe else "partially_verified") | {
            "security_findings": ["proposal contains forbidden mutation or bypass marker"] if unsafe else [],
            "severity": severity,
            "threat_checks": ["prompt_injection_and_boundary_reviewed"],
            "permission_checks": ["approval_and_scope_binding_reviewed"],
            "secret_checks": ["secret_reference_boundary_reviewed"],
            "side_effect_checks": ["side_effect_descriptors_reviewed"],
            "high_risk_execution_allowed": False,
            "extensions": {
                "proposal_evaluation": {
                    "decision": "block" if unsafe else "support",
                    "score": 0 if unsafe else 92,
                    "reason": "Forbidden side-effect or gate-bypass marker found." if unsafe else "Security boundaries preserved.",
                    "safety_issues": ["forbidden_side_effect"] if unsafe else [],
                }
            },
        }

    def _arbiter(self, payload: dict[str, Any]) -> dict[str, Any]:
        conflict_type = str(payload.get("conflict_type") or "scope_conflict")
        claims = payload.get("claims") or []
        text = json.dumps(claims, ensure_ascii=False, sort_keys=True).lower()
        policy_context = payload.get("policy_context")
        conflict_context = policy_context.get("conflict_context") if isinstance(policy_context, dict) else {}
        approval_scope = conflict_context.get("approval_scope") if isinstance(conflict_context, dict) else {}
        lease_scope_approved = isinstance(approval_scope, dict) and approval_scope.get("status") == "approved"
        if "force_arbitration_ask_user" in text:
            decision = "ask_user"
            reason = "arbitration requires user decision; fail-closed."
            winner = None
        elif "forbidden" in text or "bypass" in text or "patch_apply" in text or "force_arbitration_block" in text:
            decision = "block"
            reason = "Conflict includes forbidden action or gate bypass; fail-closed."
            winner = None
        elif conflict_type == "lease_conflict" and not lease_scope_approved:
            decision = "block"
            reason = "Conflicting write lease has no approved scope evidence; fail-closed."
            winner = None
        elif payload.get("participants"):
            decision = "grant_agent_a"
            winner = payload["participants"][0]
            reason = f"Granted first claimant for {conflict_type} after deterministic safe arbitration."
        else:
            decision = "block"
            winner = None
            reason = "No participants supplied; fail-closed."
        return self._base("arbiter", decision, verification_status="verified") | {
            "conflict_id": payload.get("conflict_id", "unknown_conflict"),
            "conflict_type": conflict_type,
            "winning_agent": winner,
            "resolution_reason": reason,
            "rework_required": decision in {"block", "ask_user"},
            "hard_gate_results": {
                "safety": False if any(marker in text for marker in ("forbidden", "bypass", "patch_apply", "force_arbitration_block")) else True,
                "permission": False if conflict_type == "lease_conflict" and not lease_scope_approved else True,
                "evidence": False if decision == "ask_user" or not payload.get("participants") else True,
            },
            "missing_authorities": ["approved_scope"] if conflict_type == "lease_conflict" and not lease_scope_approved else [],
            "extensions": {"proposal_evaluation": {"decision": "block" if decision in {"block", "ask_user"} else "support", "score": 70 if decision not in {"block", "ask_user"} else 0, "reason": reason}},
        }

    def _memory(self, payload: dict[str, Any]) -> dict[str, Any]:
        context = payload.get("memory_policy", {}).get("context", {})
        goal = str(context.get("user_goal", "")).lower()
        if "memory-agent-fail-fixture" in goal:
            raise ProviderError("mock memory failure fixture")
        if "memory-candidate-fixture" in goal:
            original_goal = str(context.get("user_goal", "memory-candidate-fixture"))
            return self._base("memory", "candidate", verification_status="partially_verified") | {
                "candidates": [
                    {
                        "content": f"User requested Sitina memory candidate fixture behavior for: {original_goal}",
                        "reason": "The user goal explicitly requested a durable memory workflow fixture.",
                        "confidence": 0.9,
                        "source": "mock_memory_agent",
                        "memory_type": "workflow_rule",
                        "sensitivity_level": "low",
                        "evidence": [{"kind": "event", "ref": "mock-memory-candidate-fixture"}],
                        "provenance_refs": ["mock-memory-candidate-fixture"],
                        "observed_at": "current_run",
                        "valid_until": None,
                        "duplicate_of": None,
                        "conflicts_with": [],
                        "privacy_decision": "eligible",
                        "status": "pending",
                    }
                ]
            }
        return self._base("memory", "none", verification_status="not_verified") | {
            "candidates": [],
            "extensions": {"no_candidate_reason": "Mock memory agent found no long-term candidate in this run."},
        }

    def _base(self, agent: str, decision: str, *, verification_status: str) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "agent": agent,
            "agent_status": "ok",
            "decision": decision,
            "evidence": [],
            "claims": [],
            "verification_status": verification_status,
            "warnings": [],
            "extensions": {},
            "budget_report": {
                "input_tokens_used": 0,
                "output_tokens_used": 0,
                "tool_tokens_used": 0,
                "run_tokens_remaining": None,
                "action": "within_budget",
            },
        }


class AgentRunner:
    def __init__(self, home: Path = SITINA_HOME):
        self.home = home
        self.store = SitinaStore(home)
        self.ledger = RunLedger(home, self.store)
        self.prompt_contracts = PromptContractRegistry(home)
        self.parser = AgentOutputParser(contract_registry=self.prompt_contracts)
        self.mock = MockProvider(home)
        self.resolver = RoleProfileResolver(home)
        self.client = AnthropicCompatibleClient(home)

    def run_agent(
        self,
        agent: str,
        input_payload: dict[str, Any],
        *,
        provider_mode: str = "mock",
        profile_override: str | None = None,
        run_id: str | None = None,
        task_id: str = "main",
        task_type: str = "chat",
        max_tokens: int | None = None,
        run_deadline: RunDeadline | None = None,
        logical_call_id: str | None = None,
        audit_context: dict[str, Any] | None = None,
    ) -> AgentRunResult:
        logical_call_id = logical_call_id or ("logical_call_" + new_id())
        safe_input_hash = compute_agent_input_hash(input_payload)
        requested_profile = profile_override
        if provider_mode == "live" and not requested_profile:
            requested_profile = self.resolver.profile_name_for_agent(agent)
        context = self._safe_audit_context(audit_context)
        started_monotonic = time.monotonic()
        self._record_logical_call_start(
            run_id=run_id,
            logical_call_id=logical_call_id,
            agent=agent,
            task_id=task_id,
            task_type=task_type,
            provider_mode=provider_mode,
            profile_name=requested_profile,
            input_hash=safe_input_hash,
            input_payload=input_payload,
            context=context,
        )
        try:
            result = self._run_agent_impl(
                agent,
                input_payload,
                provider_mode=provider_mode,
                profile_override=profile_override,
                run_id=run_id,
                task_id=task_id,
                task_type=task_type,
                max_tokens=max_tokens,
                run_deadline=run_deadline,
                logical_call_id=logical_call_id,
            )
        except BaseException as exc:
            terminal_status = self._logical_terminal_status(exc)
            details = getattr(exc, "details", {})
            details = details if isinstance(details, dict) else {}
            self._record_logical_call_terminal(
                run_id=run_id,
                logical_call_id=logical_call_id,
                agent=agent,
                task_id=task_id,
                task_type=task_type,
                provider_mode=provider_mode,
                profile_name=str(details.get("profile_name") or requested_profile or "") or None,
                model=str(details.get("model") or "") or None,
                input_hash=safe_input_hash,
                output_hash=None,
                terminal_status=terminal_status,
                duration_ms=max(0, int((time.monotonic() - started_monotonic) * 1000)),
                provider_calls=[dict(item) for item in details.get("provider_calls", []) if isinstance(item, dict)],
                fallback_used=False if provider_mode == "live" else None,
                schema_validation_status="invalid" if getattr(exc, "error_type", None) == "agent_schema_invalid" else "not_completed",
                context=context,
                error_type=str(getattr(exc, "error_type", type(exc).__name__)),
            )
            raise
        output_hash = sha256_text(stable_json(result.payload))
        result = replace(result, logical_call_id=logical_call_id)
        agent_cannot_complete = result.payload.get("agent_status") == "cannot_complete"
        self._record_logical_call_terminal(
            run_id=run_id,
            logical_call_id=logical_call_id,
            agent=agent,
            task_id=task_id,
            task_type=task_type,
            provider_mode=result.provider_mode,
            profile_name=result.profile_name,
            model=result.model,
            input_hash=safe_input_hash,
            output_hash=output_hash,
            terminal_status="failed" if agent_cannot_complete else "completed",
            duration_ms=max(0, int((time.monotonic() - started_monotonic) * 1000)),
            provider_calls=result.provider_calls,
            fallback_used=result.fallback_used,
            schema_validation_status="valid",
            context=context,
            error_type="agent_cannot_complete" if agent_cannot_complete else None,
        )
        return result

    def _run_agent_impl(
        self,
        agent: str,
        input_payload: dict[str, Any],
        *,
        provider_mode: str = "mock",
        profile_override: str | None = None,
        run_id: str | None = None,
        task_id: str = "main",
        task_type: str = "chat",
        max_tokens: int | None = None,
        run_deadline: RunDeadline | None = None,
        logical_call_id: str | None = None,
    ) -> AgentRunResult:
        validate_agent_input(agent, input_payload)
        # Prompt and its machine contract are execution preconditions in every
        # provider mode; mock runs must not hide a missing or divergent prompt.
        system_prompt = self._prompt(agent)
        if provider_mode == "mock":
            raw = self.mock.complete(agent, input_payload)
            parsed = self.parser.parse(agent, raw)
            self._checkpoint_success(run_id, agent, [], repair_attempts=0)
            return AgentRunResult(
                agent=agent,
                output=parsed.output,
                payload=parsed.payload,
                raw_text=raw,
                provider_mode="mock",
                profile_name=None,
                model=None,
                provider_identity=provider_identity_summary(None, provider_mode="mock"),
                repair_attempts=0,
                provider_calls=[],
                fallback_used=False,
            )
        if provider_mode != "live":
            raise AgentRunnerError(f"unknown provider_mode: {provider_mode}")

        config = ProviderTimeoutConfig.from_config(self.resolver.provider_config())
        retry_scheduler = RetryScheduler(
            RetrySettings(
                max_retries=config.max_retries,
                base_delay_seconds=config.retry_backoff_seconds,
                max_delay_seconds=config.retry_max_backoff_seconds,
                jitter_ratio=config.retry_jitter_ratio,
            ),
            sleep=time.sleep,
        )
        deadline = run_deadline or (RunControlStore(self.home).deadline(run_id) if run_id else None)
        try:
            self._preflight_live_call(run_id=run_id, deadline=deadline)
        except (TimeoutError, RunCancelledError) as exc:
            error = self._as_runner_error(agent, exc)
            self._record_failure(run_id, task_id, task_type, agent, error)
            raise error from exc
        # A live run has exactly one configured profile for this agent. It must
        # fail closed rather than silently changing provider/profile or mock mode.
        profile_name = profile_override or self.resolver.profile_name_for_agent(agent)
        if not profile_name:
            error = AgentRunnerError(f"{agent} has no configured live provider profile", error_type="provider_profile_missing")
            self._record_failure(run_id, task_id, task_type, agent, error)
            raise error
        user_prompt = self._user_prompt(agent, input_payload)
        profile = None
        provider_calls: list[dict[str, Any]] = []
        try:
            if isinstance(self.client, AnthropicCompatibleClient) and self.client.network_egress_capability is None:
                raise AgentRunnerError(
                    "live Provider execution requires an authorized client",
                    error_type="provider_authority_required",
                )
            profile = self.client.load_profile(profile_name)
        except ProviderError as exc:
            try:
                self.client.health.mark_unavailable(profile_name, str(exc))
            except Exception:
                # Provider Health is derived observability. Its write failure
                # must never replace the original Provider outcome.
                pass
            error = self._as_runner_error(agent, exc)
            self._record_failure(run_id, task_id, task_type, agent, error)
            raise error from exc

        completion: ProviderCompletion | None = None
        logical_call_id = logical_call_id or ("logical_call_" + new_id())
        for attempt in range(config.max_retries + 1):
            attempt_id = "provider_attempt_" + new_id()
            attempt_started_at = iso_now()
            attempt_started_monotonic = time.monotonic()
            self._record_http_attempt(
                "provider_http_attempt_started",
                run_id=run_id,
                task_id=task_id,
                task_type=task_type,
                agent=agent,
                payload={
                    "attempt_id": attempt_id,
                    "logical_call_id": logical_call_id,
                    "attempt": attempt + 1,
                    "provider_mode": "live",
                    "profile_name": profile_name,
                    "model": profile.model if profile else None,
                    "provider_call_started_at": attempt_started_at,
                    "fallback_used": False,
                },
                status="ok",
                reason="provider HTTP attempt started",
            )
            try:
                self._preflight_live_call(run_id=run_id, deadline=deadline)
                remaining = deadline.remaining_seconds() if deadline else config.total_request_timeout
                completion = self.client.complete_with_metadata(
                    profile,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=self._live_max_tokens(agent, max_tokens),
                    request_timeout_seconds=min(config.total_request_timeout, remaining),
                    expect_json=True,
                    json_schema=self._provider_json_schema(agent),
                    cancel_check=(lambda: RunControlStore(self.home).is_cancel_requested(run_id)) if run_id else None,
                )
                completed_call = dict(completion.metadata) | {
                    "attempt": attempt + 1,
                    "attempt_id": attempt_id,
                    "logical_call_id": logical_call_id,
                }
                provider_calls.append(completed_call)
                self._record_http_attempt(
                    "provider_http_attempt_completed",
                    run_id=run_id,
                    task_id=task_id,
                    task_type=task_type,
                    agent=agent,
                    payload=completed_call,
                    status="ok",
                    reason="provider HTTP attempt completed",
                )
                try:
                    self.client.health.mark_healthy(profile_name, model=profile.model)
                except Exception:
                    pass
                break
            except ProviderRateLimitError as exc:
                self._record_failed_http_attempt(run_id, task_id, task_type, agent, logical_call_id, attempt_id, attempt + 1, attempt_started_at, attempt_started_monotonic, exc, profile_name, profile.model if profile else None)
                try:
                    self.client.health.mark_unavailable(profile_name, str(exc), model=profile.model)
                except Exception:
                    pass
                remaining = deadline.remaining_seconds() if deadline else config.total_request_timeout
                schedule = retry_scheduler.plan(
                    failure_type=exc.error_type,
                    failed_attempt=attempt + 1,
                    remaining_seconds=remaining,
                    retry_after_seconds=exc.retry_after_seconds,
                    status_code=exc.status_code,
                    jitter_seed=logical_call_id,
                )
                self._record_retry(run_id, task_id, task_type, agent, schedule)
                if schedule.blocked_by_deadline:
                    error = AgentRunnerError(
                        f"{agent} rate-limit retry would exceed run deadline",
                        error_type="run_deadline_exceeded",
                        details={"retry_count": attempt + 1, "retry_after_seconds": schedule.delay_seconds},
                    )
                    self._record_failure(run_id, task_id, task_type, agent, error)
                    raise error from exc
                if not schedule.should_retry:
                    error = self._as_runner_error(agent, exc, retry_count=attempt)
                    self._record_failure(run_id, task_id, task_type, agent, error)
                    raise error from exc
                retry_scheduler.wait(schedule)
                continue
            except ProviderError as exc:
                self._record_failed_http_attempt(run_id, task_id, task_type, agent, logical_call_id, attempt_id, attempt + 1, attempt_started_at, attempt_started_monotonic, exc, profile_name, profile.model if profile else None)
                try:
                    self.client.health.mark_unavailable(profile_name, str(exc), model=profile.model)
                except Exception:
                    pass
                if isinstance(exc, ProviderReadTimeout) and deadline and deadline.is_exceeded():
                    exc = ProviderDeadlineExceeded("run deadline exceeded during provider request")
                remaining = deadline.remaining_seconds() if deadline else config.total_request_timeout
                schedule = retry_scheduler.plan(
                    failure_type=getattr(exc, "error_type", type(exc).__name__),
                    failed_attempt=attempt + 1,
                    remaining_seconds=remaining,
                    retry_after_seconds=getattr(exc, "retry_after_seconds", None),
                    status_code=getattr(exc, "status_code", None),
                    jitter_seed=logical_call_id,
                )
                self._record_retry(run_id, task_id, task_type, agent, schedule)
                if schedule.should_retry:
                    retry_scheduler.wait(schedule)
                    continue
                error = self._as_runner_error(agent, exc)
                self._record_failure(run_id, task_id, task_type, agent, error)
                raise error from exc
            except (TimeoutError, RunCancelledError) as exc:
                self._record_failed_http_attempt(run_id, task_id, task_type, agent, logical_call_id, attempt_id, attempt + 1, attempt_started_at, attempt_started_monotonic, exc, profile_name, profile.model if profile else None)
                error = self._as_runner_error(agent, exc)
                self._record_failure(run_id, task_id, task_type, agent, error)
                raise error from exc
            except Exception as exc:  # noqa: BLE001
                self._record_failed_http_attempt(run_id, task_id, task_type, agent, logical_call_id, attempt_id, attempt + 1, attempt_started_at, attempt_started_monotonic, exc, profile_name, profile.model if profile else None)
                remaining = deadline.remaining_seconds() if deadline else config.total_request_timeout
                schedule = retry_scheduler.plan(
                    failure_type=type(exc).__name__,
                    failed_attempt=attempt + 1,
                    remaining_seconds=remaining,
                    jitter_seed=logical_call_id,
                )
                self._record_retry(run_id, task_id, task_type, agent, schedule)
                if schedule.should_retry:
                    retry_scheduler.wait(schedule)
                    continue
                error = AgentRunnerError(
                    f"{agent} live provider transport failure: {redact_text(str(exc))[:500]}",
                    error_type="provider_failed",
                    details={"provider_mode": "live", "fallback_used": False, "transport_error_type": type(exc).__name__},
                )
                self._record_failure(run_id, task_id, task_type, agent, error)
                raise error from exc
        if completion is None:
            error = AgentRunnerError(f"{agent} live provider produced no completion", error_type="provider_failed")
            self._record_failure(run_id, task_id, task_type, agent, error)
            raise error

        raw = completion.text
        try:
            parsed = self.parser.parse(agent, raw)
            calls = self._validated_calls(provider_calls, agent)
            self._checkpoint_success(run_id, agent, calls, repair_attempts=0)
            return AgentRunResult(
                agent=agent,
                output=parsed.output,
                payload=parsed.payload,
                raw_text=raw,
                provider_mode="live",
                profile_name=profile_name,
                model=profile.model if profile else None,
                provider_identity=provider_identity_summary(profile, provider_mode="live", profile_name=profile_name),
                repair_attempts=0,
                provider_calls=calls,
                fallback_used=False,
            )
        except AgentParseError as first_error:
            first_artifact = self._record_parse_artifact(run_id, agent, raw, first_error, repair_attempt=0)
            budget = input_payload.get("budget") if isinstance(input_payload.get("budget"), dict) else {}
            usage = completion.metadata.get("token_usage") if isinstance(completion.metadata.get("token_usage"), dict) else {}
            default_repair_cap = self._live_max_tokens(agent, max_tokens)
            output_remaining = max(0, int(budget.get("output_token_limit", default_repair_cap)) - int(usage.get("output_tokens", 0)))
            run_remaining = max(0, int(budget.get("run_tokens_remaining", default_repair_cap)) - int(usage.get("total_tokens", 0)))
            repair_cap = min(default_repair_cap, output_remaining, run_remaining)
            if self.prompt_contracts.can_repair(
                completed_repairs=0,
                output_tokens_remaining=output_remaining,
                run_tokens_remaining=run_remaining,
            ) and repair_cap >= 64:
                repair_attempt_id = "provider_attempt_" + new_id()
                repair_started_at = iso_now()
                repair_started_monotonic = time.monotonic()
                self._record_http_attempt(
                    "provider_http_attempt_started",
                    run_id=run_id,
                    task_id=task_id,
                    task_type=task_type,
                    agent=agent,
                    payload={
                        "attempt_id": repair_attempt_id,
                        "logical_call_id": logical_call_id,
                        "attempt": len(provider_calls) + 1,
                        "repair_attempt": 1,
                        "provider_mode": "live",
                        "profile_name": profile_name,
                        "model": profile.model if profile else None,
                        "provider_call_started_at": repair_started_at,
                        "fallback_used": False,
                    },
                    status="ok",
                    reason="bounded schema repair attempt started",
                )
                try:
                    self._preflight_live_call(run_id=run_id, deadline=deadline)
                    remaining = deadline.remaining_seconds() if deadline else config.total_request_timeout
                    repaired_completion = self.client.complete_with_metadata(
                        profile,
                        system_prompt=system_prompt,
                        user_prompt=self._repair_prompt(agent, input_payload, raw, str(first_error)),
                        max_tokens=repair_cap,
                        request_timeout_seconds=min(config.total_request_timeout, remaining),
                        expect_json=True,
                        json_schema=self._provider_json_schema(agent),
                        cancel_check=(lambda: RunControlStore(self.home).is_cancel_requested(run_id)) if run_id else None,
                    )
                except Exception as repair_error:  # noqa: BLE001
                    self._record_failed_http_attempt(
                        run_id,
                        task_id,
                        task_type,
                        agent,
                        logical_call_id,
                        repair_attempt_id,
                        len(provider_calls) + 1,
                        repair_started_at,
                        repair_started_monotonic,
                        repair_error,
                        profile_name,
                        profile.model if profile else None,
                    )
                    error = AgentRunnerError(
                        f"{agent} schema repair failed: {redact_text(str(repair_error))[:500]}",
                        error_type="agent_schema_invalid",
                        details={
                            "schema_name": agent,
                            "artifact": first_artifact,
                            "raw_output_hash": sha256_text(raw),
                            "repair_attempts": 1,
                            "profile_name": profile_name,
                            "model": profile.model if profile else None,
                            "provider_calls": provider_calls,
                        },
                    )
                    self._record_failure(run_id, task_id, task_type, agent, error)
                    raise error from repair_error
                repair_call = dict(repaired_completion.metadata) | {
                    "attempt": len(provider_calls) + 1,
                    "attempt_id": repair_attempt_id,
                    "logical_call_id": logical_call_id,
                    "repair_attempt": 1,
                }
                provider_calls.append(repair_call)
                self._record_http_attempt(
                    "provider_http_attempt_completed",
                    run_id=run_id,
                    task_id=task_id,
                    task_type=task_type,
                    agent=agent,
                    payload=repair_call,
                    status="ok",
                    reason="bounded schema repair attempt completed",
                )
                repaired_raw = repaired_completion.text
                try:
                    repaired = self.parser.parse(agent, repaired_raw)
                except AgentParseError as second_error:
                    artifact = self._record_parse_artifact(run_id, agent, repaired_raw, second_error, repair_attempt=1)
                    failed_calls = [
                        dict(call)
                        | {
                            "schema_name": agent,
                            "schema_validation_status": "invalid",
                            "redaction_status": "none",
                            "fallback_used": False,
                        }
                        for call in provider_calls
                    ]
                    error = AgentRunnerError(
                        f"{agent} schema_error after bounded repair: {second_error}",
                        error_type="agent_schema_invalid",
                        details={
                            "schema_name": agent,
                            "artifact": artifact,
                            "previous_artifact": first_artifact,
                            "raw_output_hash": sha256_text(repaired_raw),
                            "repair_attempts": 1,
                            "profile_name": profile_name,
                            "model": profile.model if profile else None,
                            "provider_calls": failed_calls,
                        },
                    )
                    self._record_failure(run_id, task_id, task_type, agent, error)
                    raise error from second_error
                calls = [
                    dict(call)
                    | {
                        "schema_name": agent,
                        "schema_validation_status": "invalid" if index < len(provider_calls) - 1 else "valid",
                        "redaction_status": "none",
                        "fallback_used": False,
                    }
                    for index, call in enumerate(provider_calls)
                ]
                self._checkpoint_success(run_id, agent, calls, repair_attempts=1)
                return AgentRunResult(
                    agent=agent,
                    output=repaired.output,
                    payload=repaired.payload,
                    raw_text=repaired_raw,
                    provider_mode="live",
                    profile_name=profile_name,
                    model=profile.model if profile else None,
                    provider_identity=provider_identity_summary(profile, provider_mode="live", profile_name=profile_name),
                    repair_attempts=1,
                    provider_calls=calls,
                    fallback_used=False,
                )
            failed_calls = [
                dict(call)
                | {
                    "schema_name": agent,
                    "schema_validation_status": "invalid",
                    "redaction_status": "none",
                    "fallback_used": False,
                }
                for call in provider_calls
            ]
            error = AgentRunnerError(
                f"{agent} schema_error: {first_error}",
                error_type="agent_schema_invalid",
                details={
                    "schema_name": agent,
                    "artifact": first_artifact,
                    "raw_output_hash": sha256_text(raw),
                    "repair_attempts": 0,
                    "profile_name": profile_name,
                    "model": profile.model if profile else None,
                    "provider_calls": failed_calls,
                },
            )
            self._record_failure(run_id, task_id, task_type, agent, error)
            raise error from first_error

    @staticmethod
    def _safe_audit_context(context: dict[str, Any] | None) -> dict[str, Any]:
        if not isinstance(context, dict):
            return {}
        allowed = {
            "call_origin",
            "role",
            "dispatch_decision_id",
            "handoff_id",
            "proposal_id",
            "proposal_round_id",
            "evaluation_id",
            "rework_id",
            "retry_id",
            "arbitration_id",
            "controlled_fixture",
        }
        return {
            key: value
            for key, value in canonicalize_agent_input(context).items()
            if key in allowed and value not in (None, "", [], {})
        }

    def _record_logical_call_start(
        self,
        *,
        run_id: str | None,
        logical_call_id: str,
        agent: str,
        task_id: str,
        task_type: str,
        provider_mode: str,
        profile_name: str | None,
        input_hash: str,
        input_payload: dict[str, Any],
        context: dict[str, Any],
    ) -> None:
        if not run_id:
            return
        payload = {
            "agent_call_audit_schema_version": "1.0",
            "logical_call_id": logical_call_id,
            "phase": "started",
            "agent_id": agent,
            "role": str(context.get("role") or agent),
            "task_id": task_id,
            "task_type": task_type,
            "provider_mode": provider_mode,
            "profile_name": profile_name,
            "model": None,
            "input_hash": input_hash,
            "input_payload": canonicalize_agent_input(input_payload),
            "fallback_used": False if provider_mode == "live" else None,
            "context": context,
        }
        self.ledger.record(
            "agent_call_started",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent,
            status="ok",
            reason=f"logical agent call {logical_call_id} started",
            payload=payload,
        )
        self.store.record_audit(
            "agent_call_started",
            payload,
            run_id=run_id,
            trace_id=f"{run_id}:agent_call:{logical_call_id}:started",
            agent=agent,
            input_hash=input_hash,
            exit_status="started",
        )

    def _record_logical_call_terminal(
        self,
        *,
        run_id: str | None,
        logical_call_id: str,
        agent: str,
        task_id: str,
        task_type: str,
        provider_mode: str,
        profile_name: str | None,
        model: str | None,
        input_hash: str,
        output_hash: str | None,
        terminal_status: str,
        duration_ms: int,
        provider_calls: list[dict[str, Any]],
        fallback_used: bool | None,
        schema_validation_status: str,
        context: dict[str, Any],
        error_type: str | None = None,
    ) -> None:
        if not run_id:
            return
        linked_attempts = self._provider_attempts_for_logical_call(run_id, logical_call_id)
        if linked_attempts:
            provider_calls = linked_attempts
            profile_name = profile_name or next((str(call.get("profile_name")) for call in linked_attempts if call.get("profile_name")), None)
            model = model or next((str(call.get("model")) for call in linked_attempts if call.get("model")), None)
        provider_request_ids = sorted(
            {
                str(call.get("provider_request_id"))
                for call in provider_calls
                if call.get("provider_request_id")
            }
        )
        attempt_ids = sorted({str(call.get("attempt_id")) for call in provider_calls if call.get("attempt_id")})
        token_usage = self._aggregate_call_tokens(provider_calls)
        payload = {
            "agent_call_audit_schema_version": "1.0",
            "logical_call_id": logical_call_id,
            "phase": "terminal",
            "terminal_status": terminal_status,
            "agent_id": agent,
            "role": str(context.get("role") or agent),
            "task_id": task_id,
            "task_type": task_type,
            "provider_mode": provider_mode,
            "profile_name": profile_name,
            "model": model,
            "input_hash": input_hash,
            "output_hash": output_hash,
            "provider_request_ids": provider_request_ids,
            "attempt_ids": attempt_ids,
            "http_attempt_count": len(provider_calls),
            "token_usage": token_usage,
            "duration_ms": duration_ms,
            "schema_validation_status": schema_validation_status,
            "fallback_used": fallback_used,
            "error_type": error_type,
            "context": context,
        }
        ledger_status = "ok" if terminal_status == "completed" else "failed"
        self.ledger.record(
            "agent_call_terminal",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent,
            status=ledger_status,
            reason=f"logical agent call {logical_call_id} {terminal_status}",
            payload=payload,
        )
        self.store.record_audit(
            "agent_call_terminal",
            payload,
            run_id=run_id,
            trace_id=f"{run_id}:agent_call:{logical_call_id}:terminal",
            agent=agent,
            input_hash=input_hash,
            output_hash=output_hash,
            exit_status=terminal_status,
            duration_ms=duration_ms,
        )

    def _provider_attempts_for_logical_call(self, run_id: str, logical_call_id: str) -> list[dict[str, Any]]:
        attempts = [
            dict(event.get("payload_json") or {})
            for event in self.ledger.timeline(run_id)
            if event.get("event_type") in {"provider_http_attempt_completed", "provider_http_attempt_failed"}
            and (event.get("payload_json") or {}).get("logical_call_id") == logical_call_id
        ]
        attempts.sort(key=lambda item: int(item.get("attempt") or 0))
        return attempts

    @staticmethod
    def _aggregate_call_tokens(provider_calls: list[dict[str, Any]]) -> dict[str, int] | None:
        totals: dict[str, int] = {}
        for call in provider_calls:
            usage = call.get("token_usage")
            if not isinstance(usage, dict):
                continue
            for key in ("input_tokens", "output_tokens", "total_tokens", "cache_read_tokens", "cache_write_tokens"):
                value = usage.get(key)
                if isinstance(value, int) and value >= 0:
                    totals[key] = totals.get(key, 0) + value
        return totals or None

    @staticmethod
    def _logical_terminal_status(exc: BaseException) -> str:
        error_type = str(getattr(exc, "error_type", getattr(exc, "timeout_type", "")))
        if isinstance(exc, KeyboardInterrupt) or error_type == "run_cancelled":
            return "cancelled"
        if error_type in {"run_deadline", "run_deadline_exceeded", "provider_connect_timeout", "provider_read_timeout"}:
            return "timeout"
        return "failed"

    def _preflight_live_call(self, *, run_id: str | None, deadline: RunDeadline | None) -> None:
        if run_id and RunControlStore(self.home).is_cancel_requested(run_id):
            raise RunCancelledError(RunControlStore(self.home).cancel_reason(run_id))
        if deadline and deadline.is_exceeded():
            raise TimeoutError("run_deadline", "run deadline exceeded before provider call")

    def _live_max_tokens(self, agent: str, requested: int | None) -> int:
        role_defaults = {
            "controller": 2048,
            "planner": 4096,
            "architect": 4096,
            "coder": 4096,
            "tester": 4096,
            "reviewer": 4096,
            "security": 4096,
            "critic": 4096,
            "arbiter": 1024,
            "researcher": 2048,
            "summary": 4096,
            "memory": 4096,
        }
        provider_config = self.resolver.provider_config()
        try:
            configured_cap = max(64, int(provider_config.get("max_live_tokens_per_agent", 4096)))
        except (TypeError, ValueError):
            configured_cap = 4096
        target = int(requested) if requested is not None else role_defaults.get(agent, 1536)
        return max(64, min(target, configured_cap))

    def _validated_calls(self, calls: list[dict[str, Any]], schema_name: str) -> list[dict[str, Any]]:
        return [
            dict(call)
            | {
                "schema_name": schema_name,
                "schema_validation_status": "valid",
                "redaction_status": "none",
                "fallback_used": False,
            }
            for call in calls
        ]

    def _as_runner_error(self, agent: str, exc: Exception, *, retry_count: int | None = None) -> AgentRunnerError:
        if isinstance(exc, RunCancelledError):
            error_type = "run_cancelled"
        elif isinstance(exc, TimeoutError | ProviderDeadlineExceeded):
            error_type = "run_deadline_exceeded"
        elif isinstance(exc, ProviderConnectTimeout):
            error_type = "provider_connect_timeout"
        elif isinstance(exc, ProviderReadTimeout):
            error_type = "provider_read_timeout"
        elif isinstance(exc, ProviderAuthError):
            error_type = "provider_auth_failed"
        elif isinstance(exc, ProviderPermissionError):
            error_type = "provider_permission_denied"
        elif isinstance(exc, ProviderRateLimitError):
            error_type = "provider_rate_limited"
        elif isinstance(exc, ProviderMalformedResponse):
            error_type = "provider_parse_failed"
        else:
            error_type = getattr(exc, "error_type", "provider_failed")
        details: dict[str, Any] = {"provider_mode": "live", "fallback_used": False}
        if retry_count is not None:
            details["retry_count"] = retry_count
        if isinstance(exc, ProviderRateLimitError):
            details["retry_after_seconds"] = exc.retry_after_seconds
        return AgentRunnerError(f"{agent} live provider failure: {redact_text(str(exc))[:500]}", error_type=error_type, details=details)

    def _record_retry(self, run_id: str | None, task_id: str, task_type: str, agent: str, schedule: RetrySchedule) -> None:
        if not run_id:
            return
        RunLedger(self.home).record(
            "provider_retry_scheduled" if schedule.should_retry else "provider_retry_denied",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent,
            status="warning" if schedule.should_retry else "blocked",
            reason=schedule.reason,
            payload=schedule.mapping()
            | {
                "retry_count": schedule.failed_attempt,
                "retry_after_seconds": schedule.delay_seconds,
                "provider_mode": "live",
                "fallback_used": False,
            },
        )

    def _record_failed_http_attempt(
        self,
        run_id: str | None,
        task_id: str,
        task_type: str,
        agent: str,
        logical_call_id: str,
        attempt_id: str,
        attempt: int,
        started_at: str,
        started_monotonic: float,
        exc: Exception,
        profile_name: str,
        model: str | None,
    ) -> None:
        payload = {
            "attempt_id": attempt_id,
            "logical_call_id": logical_call_id,
            "attempt": attempt,
            "provider_mode": "live",
            "profile_name": profile_name,
            "model": model,
            "provider_call_started_at": started_at,
            "provider_call_completed_at": iso_now(),
            "duration_ms": max(0, int((time.monotonic() - started_monotonic) * 1000)),
            "error_type": getattr(exc, "error_type", type(exc).__name__),
            "status_code": getattr(exc, "status_code", None),
            "fallback_used": False,
        }
        self._record_http_attempt(
            "provider_http_attempt_failed",
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent=agent,
            payload=payload,
            status="failed",
            reason=f"provider HTTP attempt failed: {payload['error_type']}",
        )

    def _record_http_attempt(
        self,
        event_type: str,
        *,
        run_id: str | None,
        task_id: str,
        task_type: str,
        agent: str,
        payload: dict[str, Any],
        status: str,
        reason: str,
    ) -> None:
        if not run_id:
            return
        RunLedger(self.home).record(
            event_type,
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent,
            status=status,  # type: ignore[arg-type]
            reason=reason,
            payload=payload,
        )

    def _record_failure(self, run_id: str | None, task_id: str, task_type: str, agent: str, error: AgentRunnerError) -> None:
        if not run_id:
            return
        event_type = error.error_type if error.error_type in {
            "provider_connect_timeout", "provider_read_timeout", "run_deadline_exceeded", "run_cancelled",
            "provider_auth_failed", "provider_permission_denied", "provider_rate_limited", "provider_parse_failed",
            "agent_schema_invalid", "provider_profile_missing", "provider_failed",
        } else "provider_failed"
        RunLedger(self.home).record(
            event_type,
            run_id=run_id,
            task_id=task_id,
            task_type=task_type,
            agent_id=agent,
            status="failed",
            reason=redact_text(str(error))[:500],
            payload={"error_type": error.error_type, **error.details, "fallback_used": False},
        )

    def _record_parse_artifact(self, run_id: str | None, agent: str, raw: str, error: AgentParseError, *, repair_attempt: int) -> str | None:
        if not run_id:
            return None
        path = self.home / "artifacts" / "provider_parse_failures" / run_id / f"{agent}-{repair_attempt}.json"
        ensure_dir(path.parent)
        write_json(
            path,
            {
                "run_id": run_id,
                "agent": agent,
                "schema_name": agent,
                "error_type": "agent_parse_error",
                "error": redact_text(str(error))[:500],
                "raw_output_hash": sha256_text(raw),
                "raw_output_preview": redact_text(raw)[:500],
                "redaction_status": "none",
                "repair_attempt": repair_attempt,
                "created_at": iso_now(),
            },
        )
        RunLedger(self.home).record(
            "provider_parse_failed",
            run_id=run_id,
            agent_id=agent,
            status="failed",
            reason=redact_text(str(error))[:500],
            artifacts=[str(path)],
            payload={
                "schema_name": agent,
                "error_type": "agent_parse_error",
                "raw_output_hash": sha256_text(raw),
                "redaction_status": "none",
                "repair_attempt": repair_attempt,
                "fallback_used": False,
            },
        )
        return str(path)

    def _checkpoint_success(self, run_id: str | None, agent: str, provider_calls: list[dict[str, Any]], *, repair_attempts: int) -> None:
        if not run_id:
            return
        try:
            from sitina.orchestrator.checkpoint import CheckpointManager

            CheckpointManager(self.home).create(
                run_id=run_id,
                stage=f"{agent}_completed",
                completed_agent_calls=[{"agent_id": agent, "provider_calls": provider_calls, "repair_attempts": repair_attempts}],
            )
        except Exception as exc:  # noqa: BLE001
            error = AgentRunnerError(
                f"checkpoint write failed after {agent}: {redact_text(str(exc))[:500]}",
                error_type="checkpoint_failed",
                details={"agent": agent},
            )
            self._record_failure(run_id, "main", "chat", agent, error)
            raise error from exc

    def _coder_fallback_allowed(self, input_payload: dict[str, Any]) -> bool:
        return bool(
            input_payload.get("approval_id")
            and input_payload.get("approved_touched_files")
            and input_payload.get("allowed_scope")
            and input_payload.get("input_scope_hash")
        )

    def _prompt(self, agent: str) -> str:
        try:
            return self.prompt_contracts.render(agent)
        except Exception as exc:  # noqa: BLE001
            raise AgentRunnerError(f"prompt contract invalid for {agent}: {exc}", error_type="agent_prompt_invalid") from exc

    def _output_json_schema(self, agent: str) -> dict[str, Any] | None:
        path = self.home / "schemas" / f"{agent}.schema.json"
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None
        return value if isinstance(value, dict) else None

    def _provider_json_schema(self, agent: str) -> dict[str, Any] | None:
        # DeepSeek tool arguments may duplicate large summaries and architect
        # proposal objects. JSON framing still receives full Pydantic validation.
        return None if agent in {"architect", "coder", "summary"} else self._output_json_schema(agent)

    def _user_prompt(self, agent: str, input_payload: dict[str, Any]) -> str:
        schema_path = self.home / "schemas" / f"{agent}.schema.json"
        schema_text = schema_path.read_text(encoding="utf-8") if schema_path.exists() else "{}"
        handoff_instruction = ""
        if self._is_handoff_decision_request(input_payload):
            handoff_instruction = (
                "\nHANDOFF DECISION: You are the receiver. Inspect handoff_contract and return your own decision in "
                "extensions.handoff_decision as an object with decision=accept|reject, a concrete reason, and confidence 0..1. "
                "The runtime has already validated contract preconditions. Reject only for a concrete contradiction, missing contract evidence, "
                "or a safety violation visible in the supplied contract/context; do not infer a decision from goal text alone. "
                "When handoff_context contains controlled_reject_evidence, treat its fields as runtime-supplied facts and independently decide whether they prove a scope or safety conflict. "
                "When context declares a controlled_noop_policy_graph, its code_change label exercises policy gates only and does not authorize real mutation.\n"
            )
        debate_instruction = ""
        if self._is_debate_response(input_payload):
            debate_instruction = (
                "\nCOMPACT DEBATE RESPONSE: Answer only the supplied critique. Keep every string short, use at most two "
                "plan steps and two claims, and do not restate full proposals or embed JSON inside a JSON string. Avoid quote "
                "characters inside string values. Put the specific defense or correction only in extensions.proposal_bid.\n"
            )
        readonly_instruction = ""
        readonly_contract = self._readonly_analysis_contract(input_payload)
        if readonly_contract:
            readonly_instruction = (
                "\nREADONLY ANALYSIS CONTRACT: The runtime has already collected the listed local module inventory without mutation. "
                "For a proposal, include extensions.proposal_bid.task_graph_patch with strategy=readonly_architecture_analysis, "
                "side_effects=forbidden, analysis_scope for all listed modules, and runtime_behavior_checks for replay/timeout boundaries. "
                "extensions.proposal_bid.expected_artifacts must contain readonly_module_inventory and architecture_consistency_report; "
                "required_gates must contain tester, reviewer, memory_check, and sensitive_path_review; verification_plan must verify "
                "inventory/report hashes, the exact listed read scope, no subprocess or dynamic execution, no network/source mutation, "
                "the bounded deadline, and that later repository changes are unverified, using at most two concise verification strings. "
                "The actual runtime uses Path.read_text only. Do not mention or propose AST, ast.parse, a script, dynamic imports, locking, "
                "or hash-based concurrency controls. The inventory is only a start-of-run snapshot; later repository changes are outside scope and "
                "must be stated as unverified. Treat unavailable runtime behavior as an explicitly unverified limitation rather than inventing a "
                "control or safety defect. Do not call this a no-op placeholder and do not claim the report already exists. No source "
                "write, git operation, or external side effect is permitted.\n"
            )
        arbitration_instruction = ""
        if agent == "arbiter":
            policy_context = input_payload.get("policy_context")
            conflict_context = policy_context.get("conflict_context") if isinstance(policy_context, dict) else None
            author_map = conflict_context.get("proposal_author_map") if isinstance(conflict_context, dict) else None
            participants = input_payload.get("participants")
            if isinstance(author_map, dict) and isinstance(participants, list) and len(participants) >= 2:
                arbitration_instruction = (
                    "\nARBITRATION AUTHORSHIP: policy_context.conflict_context.proposal_author_map maps proposal IDs to their authors, "
                    "and selection identifies the selected proposal. Participants are ordered as agent_a then agent_b. If evidence supports "
                    "the selected proposal, use grant_agent_a or grant_agent_b for its mapped author and set winning_agent to that exact author. "
                    "Do not claim authorship is missing when this mapping is present. Block only for a concrete unresolved conflict in the supplied evidence.\n"
                )
            approval_scope = conflict_context.get("approval_scope") if isinstance(conflict_context, dict) else None
            if input_payload.get("conflict_type") == "lease_conflict" and isinstance(approval_scope, dict):
                arbitration_instruction += (
                    "\nLEASE ARBITRATION: A lease decision only reserves a resource; it never authorizes a file mutation or bypasses later approval gates. "
                    "When the supplied approval_scope is current and bound to one participant, treat it as evidence for that participant's reservation. "
                    "Do not block solely because real mutation remains forbidden in this fixture. If approval_scope.enforcement is "
                    "block_required_without_approval, return decision=block rather than ask_user. Otherwise, if no participant has a current approved scope, block or ask_user.\n"
                )
        evaluation_instruction = ""
        if agent in {"critic", "reviewer"} and self._is_proposal_evaluation(input_payload):
            evaluation_instruction = (
                "\nCOMPACT EVALUATION: Return at most two claims, two evidence entries, two objections/findings, and two required changes. "
                "Keep every reason and string under 240 ASCII characters. Quote only concrete evidence in the supplied proposal or contract. "
                "For a readonly contract, missing runtime behavior must be labeled unverified rather than a blocker unless the supplied evidence "
                "shows a concrete policy violation.\n"
            )
        proposal_instruction = ""
        if self._is_proposal_authoring(input_payload):
            project_context = input_payload.get("project_context") if isinstance(input_payload.get("project_context"), dict) else {}
            minimal_contract = project_context.get("minimal_live_contract") if isinstance(project_context.get("minimal_live_contract"), dict) else None
            contract_fields = (
                " For minimal_live_contract also include required_tools=[], required_side_effects=[], read_paths exactly as supplied, "
                "write_paths=[], writable_scope=[], and touched_files=[]."
                if minimal_contract
                else ""
            )
            proposal_instruction = (
                "\nCOMPACT PROPOSAL: Set top-level evidence=[], claims=[], and warnings=[]. Use at most two plan steps and one item in each "
                "role-specific decision/rollback/boundary array. Keep all strings under 180 characters. Do not embed JSON, markdown, comments, "
                "or quoted documents inside string values. extensions must contain only proposal_bid. In proposal_bid include only summary, "
                "proposal_type, task_graph_patch, required_gates, verification_plan, expected_artifacts, confidence, and safety_notes; use at most "
                f"two verification items and one safety note. Omit every other optional bid field.{contract_fields}\n"
            )
        readonly_verification_instruction = ""
        if self._is_controlled_readonly_verification(agent, input_payload):
            readonly_verification_instruction = (
                "\nCONTROLLED READONLY VERIFICATION: The runtime has supplied local readonly inventory/report evidence and has not requested "
                "a command, patch, or tool call. Do not report cannot_complete merely because no command is needed. Return pass/accept only when "
                "the supplied evidence confirms no source mutation, required proposal/evaluation evidence, and a valid predecessor result; otherwise "
                "return fail/request_changes with a concrete supplied-evidence reason. Use at most one claim, one evidence item, and one finding; "
                "keep every string under 180 characters and leave optional arrays empty when there is no issue.\n"
            )
        typed_rework_instruction = ""
        if agent == "tester" and "typed rework probe" in str(input_payload.get("test_strategy") or "").lower():
            typed_rework_instruction = (
                "\nTYPED REWORK PROBE: The supplied initial verification artifact is intentionally absent. Do not invent evidence or report pass. "
                "This is an evidence-only decision; do not return cannot_complete because no command or source write is required. "
                "Return decision=fail, verification_status=not_verified, and extensions.rework_failure as an object with "
                "failure_type=missing_evidence, severity=major, retryable=true, and a concrete reason tied to the absent artifact.\n"
            )
        controlled_rework_coder_instruction = ""
        plan = input_payload.get("plan")
        if agent == "coder" and isinstance(plan, dict) and isinstance(plan.get("rework_contract"), dict):
            controlled_rework_coder_instruction = (
                "\nCONTROLLED REWORK CODER: This repair creates an evidence descriptor only; no source write or tool call is authorized. "
                "Do not return cannot_complete merely because mutation is forbidden. Return decision=unchanged, scope_compliance=in_scope, "
                "and a concise extensions.rework_descriptor describing how the supplied missing-evidence failure is repaired. "
                "Do not claim a file was written.\n"
            )
        return (
            "Return exactly one JSON object matching the schema. No markdown, no commentary. "
            "Schema discipline: extensions must always be an object (use {} when empty), evidence and claims must always be arrays, "
            "and do not use null for object or array fields. Each evidence item may contain only ref, kind, and trust_level; kind must be artifact, file, url, obsidian, audit, or event; "
            "put explanatory prose in claims.text, never evidence.\n\n"
            f"AGENT: {agent}\n"
            f"INPUT_SHA256: {sha256_text(stable_json(input_payload))}\n"
            f"INPUT_JSON:\n{json.dumps(input_payload, ensure_ascii=False, sort_keys=True)}\n\n"
            f"{handoff_instruction}\n"
            f"{debate_instruction}\n"
            f"{readonly_instruction}\n"
            f"{arbitration_instruction}\n"
            f"{evaluation_instruction}\n"
            f"{proposal_instruction}\n"
            f"{readonly_verification_instruction}\n"
            f"{typed_rework_instruction}\n"
            f"{controlled_rework_coder_instruction}\n"
            f"OUTPUT_JSON_SCHEMA:\n{schema_text}\n"
        )

    @staticmethod
    def _is_debate_response(input_payload: dict[str, Any]) -> bool:
        project_context = input_payload.get("project_context")
        current_plan = input_payload.get("current_plan")
        return bool(
            isinstance(project_context, dict) and project_context.get("debate_context")
            or isinstance(current_plan, dict) and current_plan.get("debate_context")
        )

    @staticmethod
    def _readonly_analysis_contract(input_payload: dict[str, Any]) -> dict[str, Any] | None:
        project_context = input_payload.get("project_context")
        current_plan = input_payload.get("current_plan")
        if isinstance(project_context, dict) and isinstance(project_context.get("readonly_analysis_contract"), dict):
            return project_context["readonly_analysis_contract"]
        if isinstance(current_plan, dict) and isinstance(current_plan.get("readonly_analysis_contract"), dict):
            return current_plan["readonly_analysis_contract"]
        return None

    @staticmethod
    def _is_proposal_evaluation(input_payload: dict[str, Any]) -> bool:
        current_plan = input_payload.get("current_plan")
        if isinstance(current_plan, dict) and isinstance(current_plan.get("proposal"), dict):
            return True
        mandatory_context = input_payload.get("mandatory_step_context")
        return isinstance(mandatory_context, dict) and isinstance(mandatory_context.get("proposal"), dict)

    @staticmethod
    def _is_proposal_authoring(input_payload: dict[str, Any]) -> bool:
        project_context = input_payload.get("project_context")
        if isinstance(project_context, dict) and project_context.get("collaboration_mode") == "proposal_authoring":
            return True
        current_plan = input_payload.get("current_plan")
        return isinstance(current_plan, dict) and isinstance(current_plan.get("team_selection"), dict)

    @staticmethod
    def _is_handoff_decision_request(input_payload: dict[str, Any]) -> bool:
        def contains_flag(value: Any) -> bool:
            if isinstance(value, dict):
                return bool(value.get("handoff_decision_request")) or any(contains_flag(item) for item in value.values())
            if isinstance(value, list):
                return any(contains_flag(item) for item in value)
            return False

        return contains_flag(input_payload)

    @staticmethod
    def _is_controlled_readonly_verification(agent: str, input_payload: dict[str, Any]) -> bool:
        if agent == "tester":
            return input_payload.get("patch_id") == "live_readonly_analysis" and bool(input_payload.get("blackboard_context"))
        if agent == "reviewer":
            context = input_payload.get("mandatory_step_context")
            return isinstance(context, dict) and isinstance(context.get("readonly_analysis"), dict)
        return False

    def _repair_prompt(self, agent: str, input_payload: dict[str, Any], previous_output: str, error: str) -> str:
        return (
            "Your previous output failed strict Sitina JSON/schema validation. Repair once.\n"
            "Return exactly one JSON object, no markdown and no prose.\n\n"
            f"ERROR: {error}\n"
            f"PREVIOUS_OUTPUT:\n{previous_output}\n\n"
            f"{self._user_prompt(agent, input_payload)}"
        )
