from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from sitina.constants import AGENTS, SITINA_HOME
from sitina.utils import load_json_yaml, sha256_text, stable_json


CONTRACT_BEGIN = "SITINA_MACHINE_CONTRACT_BEGIN"
CONTRACT_END = "SITINA_MACHINE_CONTRACT_END"


class PromptContractError(RuntimeError):
    pass


class PromptContractRegistry:
    """Loads, verifies and renders the authoritative contract for every agent prompt."""

    def __init__(self, home: Path = SITINA_HOME):
        self.home = Path(home).resolve()
        self.path = self.home / "config" / "agent_prompt_contracts.json"

    def _load_object(self, path: Path, *, label: str) -> dict[str, Any]:
        if not path.exists():
            raise PromptContractError(f"{label} missing: {path}")
        try:
            value = load_json_yaml(path)
        except Exception as exc:  # noqa: BLE001
            raise PromptContractError(f"{label} unreadable: {exc}") from exc
        if not isinstance(value, dict):
            raise PromptContractError(f"{label} must be an object")
        return value

    def load(self) -> dict[str, Any]:
        value = self._load_object(self.path, label="agent prompt contract")
        errors = self.validate(value)
        if errors:
            raise PromptContractError("; ".join(errors))
        return value

    def _resolve(self, relative: str) -> Path:
        path = (self.home / relative).resolve()
        if not path.is_relative_to(self.home):
            raise PromptContractError(f"prompt contract path escapes home: {relative}")
        return path

    @staticmethod
    def _agent_const(schema: Mapping[str, Any]) -> str | None:
        agent = schema.get("properties", {}).get("agent", {}) if isinstance(schema.get("properties"), dict) else {}
        if isinstance(agent, dict) and isinstance(agent.get("const"), str):
            return str(agent["const"])
        return None

    def validate(self, value: Mapping[str, Any] | None = None) -> list[str]:
        errors: list[str] = []
        if value is None:
            try:
                value = self._load_object(self.path, label="agent prompt contract")
            except PromptContractError as exc:
                return [str(exc)]
        if value.get("schema") != "SITINA_AGENT_PROMPT_CONTRACTS_V1" or value.get("version") != "1.0":
            errors.append("agent prompt contract schema/version mismatch")
        shared = value.get("shared")
        roles = value.get("roles")
        matrix = value.get("responsibility_matrix")
        if not isinstance(shared, dict) or not isinstance(roles, dict) or not isinstance(matrix, dict):
            return errors + ["agent prompt contract requires shared, roles and responsibility_matrix objects"]
        if set(roles) != set(AGENTS):
            errors.append(f"agent prompt contract roles mismatch: {sorted(set(roles) ^ set(AGENTS))}")

        try:
            agents_config = self._load_object(self.home / "config" / "agents.yaml", label="agents config").get("agents", {})
        except PromptContractError as exc:
            errors.append(str(exc))
            agents_config = {}
        for agent in sorted(set(AGENTS) & set(roles)):
            role = roles[agent]
            if not isinstance(role, dict):
                errors.append(f"prompt role contract must be an object: {agent}")
                continue
            required_role_fields = {"prompt", "output_schema", "upstream", "downstream", "read_write", "completion", "escalation", "required_output_fields"}
            missing_role = sorted(required_role_fields - set(role))
            if missing_role:
                errors.append(f"prompt role contract {agent} missing fields: {missing_role}")
                continue
            try:
                prompt_path = self._resolve(str(role["prompt"]))
                schema_path = self._resolve(str(role["output_schema"]))
            except PromptContractError as exc:
                errors.append(str(exc))
                continue
            if not prompt_path.exists() or not prompt_path.read_text(encoding="utf-8").strip():
                errors.append(f"prompt missing or empty for {agent}: {prompt_path}")
            try:
                schema = self._load_object(schema_path, label=f"output schema for {agent}")
            except PromptContractError as exc:
                errors.append(str(exc))
                continue
            if self._agent_const(schema) != agent:
                errors.append(f"output schema agent const mismatch for {agent}")
            properties = schema.get("properties", {}) if isinstance(schema.get("properties"), dict) else {}
            absent_output_fields = sorted(set(role["required_output_fields"]) - set(properties))
            if absent_output_fields:
                errors.append(f"prompt role {agent} references unknown output fields: {absent_output_fields}")
            configured = agents_config.get(agent, {}) if isinstance(agents_config, dict) else {}
            expected_pointer = f"config/agent_prompt_contracts.json#/roles/{agent}"
            if not isinstance(configured, dict) or configured.get("prompt_contract") != expected_pointer:
                errors.append(f"agents config prompt_contract mismatch for {agent}")
            if isinstance(configured, dict) and (configured.get("prompt") != role["prompt"] or configured.get("output_schema") != role["output_schema"]):
                errors.append(f"agents config prompt/schema mismatch for {agent}")

        repair = shared.get("repair_contract", {})
        if not isinstance(repair, dict) or repair.get("maximum_schema_repairs") != 1:
            errors.append("schema repair must be bounded to exactly one attempt")
        budget = shared.get("budget_contract", {})
        if not isinstance(budget, dict) or set(budget.get("input_fields", [])) != {
            "input_token_limit", "output_token_limit", "tool_token_limit", "run_token_limit", "run_tokens_remaining"
        }:
            errors.append("agent budget input contract is incomplete")
        evaluation = shared.get("evaluation_contract", {})
        try:
            policy = self._load_object(self.home / "config" / "proposal_review_policy.json", label="proposal review policy")
            rubric = policy.get("rubric", {})
            if not isinstance(evaluation, dict) or evaluation.get("version") != rubric.get("version"):
                errors.append("prompt evaluation rubric version diverges from proposal review policy")
            elif evaluation.get("weights_ppm") != rubric.get("weights_ppm") or evaluation.get("hard_gates") != rubric.get("hard_gates"):
                errors.append("prompt evaluation rubric values diverge from proposal review policy")
        except PromptContractError as exc:
            errors.append(str(exc))

        expected_owners = {
            "problem_discovery": "critic",
            "rubric_scoring": "evaluator",
            "acceptance_gate": "reviewer",
            "conflict_resolution": "arbiter",
        }
        actual_owners = {
            name: entry.get("owner")
            for name, entry in matrix.items()
            if isinstance(entry, dict)
        }
        if actual_owners != expected_owners:
            errors.append("responsibility matrix owner or function mismatch")
        return errors

    def role(self, agent: str) -> dict[str, Any]:
        if agent not in AGENTS:
            raise PromptContractError(f"unknown agent prompt contract: {agent}")
        return dict(self.load()["roles"][agent])

    def render(self, agent: str) -> str:
        contract = self.load()
        role = contract["roles"][agent]
        prompt_path = self._resolve(str(role["prompt"]))
        static_prompt = prompt_path.read_text(encoding="utf-8").strip()
        bundle = {
            "schema": contract["schema"],
            "version": contract["version"],
            "role": agent,
            "role_contract": role,
            "shared_contract": contract["shared"],
            "responsibility_matrix": contract["responsibility_matrix"],
            "contract_hash": sha256_text(stable_json({
                "schema": contract["schema"],
                "version": contract["version"],
                "role": agent,
                "role_contract": role,
                "shared_contract": contract["shared"],
                "responsibility_matrix": contract["responsibility_matrix"],
            })),
        }
        return (
            f"{static_prompt}\n\n"
            "## Machine-verifiable contract\n\n"
            "The JSON between the sentinels is authoritative. Follow its referenced schemas and policies; do not invent output fields.\n"
            f"{CONTRACT_BEGIN}\n{stable_json(bundle)}\n{CONTRACT_END}\n"
        )

    @staticmethod
    def parse_rendered(rendered: str) -> dict[str, Any]:
        if rendered.count(CONTRACT_BEGIN) != 1 or rendered.count(CONTRACT_END) != 1:
            raise PromptContractError("rendered prompt must contain exactly one machine contract")
        raw = rendered.split(CONTRACT_BEGIN, 1)[1].split(CONTRACT_END, 1)[0].strip()
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PromptContractError(f"rendered machine contract is invalid JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise PromptContractError("rendered machine contract must be an object")
        expected = value.get("contract_hash")
        unsigned = {key: item for key, item in value.items() if key != "contract_hash"}
        if expected != sha256_text(stable_json(unsigned)):
            raise PromptContractError("rendered machine contract hash mismatch")
        return value

    def validate_output_payload(self, agent: str, payload: Mapping[str, Any]) -> None:
        role = self.role(agent)
        missing = sorted(set(role["required_output_fields"]) - set(payload))
        if missing:
            raise PromptContractError(f"{agent} output missing prompt-contract fields: {missing}")
        if payload.get("agent") != agent:
            raise PromptContractError(f"{agent} output agent identity mismatch")
        budget = payload.get("budget_report")
        if not isinstance(budget, dict) or budget.get("action") not in {"within_budget", "compressed", "escalated", "blocked"}:
            raise PromptContractError(f"{agent} output budget_report is invalid")
        self._validate_claims(payload)
        if agent == "planner":
            confidence = payload.get("confidence")
            if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
                raise PromptContractError("planner confidence must be within 0..1")
        if agent == "reviewer":
            recommendation = payload.get("overall_recommendation")
            if recommendation != "accept" and not isinstance(payload.get("rejection"), dict):
                raise PromptContractError("non-accept reviewer output requires structured rejection")
        if agent == "arbiter":
            gates = payload.get("hard_gate_results")
            if not isinstance(gates, dict) or set(gates) != {"safety", "permission", "evidence"}:
                raise PromptContractError("arbiter must report safety, permission and evidence hard gates")
            if any(value is not True for value in gates.values()) and payload.get("decision") not in {"block", "ask_user"}:
                raise PromptContractError("arbiter must fail closed when a hard gate is false or missing")
        if agent == "security" and payload.get("high_risk_execution_allowed") is not False:
            raise PromptContractError("security agent cannot authorize high-risk execution")
        if agent == "memory":
            for candidate in payload.get("candidates", []):
                if not isinstance(candidate, dict) or candidate.get("status") != "pending" or candidate.get("privacy_decision") not in {"eligible", "review", "reject"}:
                    raise PromptContractError("memory candidates must remain pending with a privacy decision")

    @staticmethod
    def _validate_claims(payload: Mapping[str, Any]) -> None:
        claim_groups = [payload.get("claims", [])]
        for name in ("original_requirement_assessment", "facts", "inferences"):
            claim_groups.append(payload.get(name, []))
        for group in claim_groups:
            if not isinstance(group, list):
                raise PromptContractError("claim group must be an array")
            for claim in group:
                if not isinstance(claim, dict):
                    raise PromptContractError("claim must be an object")
                required = {"text", "label", "source_ref", "evidence_ref", "observed_at"}
                if required - set(claim) or not claim.get("source_ref") or not claim.get("observed_at"):
                    raise PromptContractError("material claims require trust label, source, evidence and observed_at")

    def can_repair(self, *, completed_repairs: int, output_tokens_remaining: int, run_tokens_remaining: int) -> bool:
        maximum = int(self.load()["shared"]["repair_contract"]["maximum_schema_repairs"])
        return completed_repairs < maximum and output_tokens_remaining > 0 and run_tokens_remaining > 0


__all__ = ["CONTRACT_BEGIN", "CONTRACT_END", "PromptContractError", "PromptContractRegistry"]
