from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from sitina.schemas.models import CommonAgentOutput, validate_agent_output
from sitina.runners.prompt_contracts import PromptContractError, PromptContractRegistry
from sitina.runners.provider import _attempt_json_repair


class AgentParseError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedAgentOutput:
    output: CommonAgentOutput
    payload: dict[str, Any]


class AgentOutputParser:
    def __init__(self, contract_registry: PromptContractRegistry | None = None):
        self.contract_registry = contract_registry

    def parse(self, agent: str, text: str) -> ParsedAgentOutput:
        payload = self.parse_single_json(text)
        try:
            if self.contract_registry is not None:
                self.contract_registry.validate_output_payload(agent, payload)
            output = validate_agent_output(agent, payload)
        except ValidationError as exc:
            raise AgentParseError(f"{agent} output schema_error: {exc}") from exc
        except ValueError as exc:
            raise AgentParseError(f"{agent} output schema_error: {exc}") from exc
        except PromptContractError as exc:
            raise AgentParseError(f"{agent} output prompt_contract_error: {exc}") from exc
        return ParsedAgentOutput(output=output, payload=output.model_dump())

    def parse_single_json(self, text: str) -> dict[str, Any]:
        stripped = text.strip()
        fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", stripped, flags=re.DOTALL)
        if fenced:
            stripped = fenced.group(1).strip()
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            # Attempt to repair malformed JSON from DeepSeek and other providers
            import sys
            print(f"[AGENT_PARSER] JSON parse failed, attempting repair", file=sys.stderr)
            print(f"[AGENT_PARSER] Raw text (first 300 chars): {stripped[:300]}", file=sys.stderr)

            repaired = _attempt_json_repair(stripped)
            if repaired is not None:
                payload = repaired
                print(f"[AGENT_PARSER] JSON repair succeeded!", file=sys.stderr)
            else:
                print(f"[AGENT_PARSER] JSON repair failed", file=sys.stderr)
                raise AgentParseError(f"agent output must be one JSON object: {exc}") from exc
        if not isinstance(payload, dict):
            raise AgentParseError("agent output must be a JSON object")
        return payload
