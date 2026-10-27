from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from sitina.schemas.models import CommonAgentOutput, validate_agent_output
from sitina.runners.prompt_contracts import PromptContractError, PromptContractRegistry
from sitina.runners.provider import parse_complete_json_object


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
            # Pydantic's formatted error includes input values. Keep locations
            # and error types useful for correction without logging payloads.
            issues = [{"loc": item["loc"], "type": item["type"]} for item in exc.errors()]
            raise AgentParseError(f"{agent} output schema_error: {issues}") from None
        except PromptContractError:
            raise AgentParseError(f"{agent} output prompt_contract_error") from None
        except ValueError:
            raise AgentParseError(f"{agent} output schema_error") from None
        return ParsedAgentOutput(output=output, payload=output.model_dump())

    def parse_single_json(self, text: str) -> dict[str, Any]:
        stripped = text.strip()
        fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", stripped, flags=re.DOTALL)
        if fenced:
            stripped = fenced.group(1).strip()
        try:
            payload = parse_complete_json_object(stripped)
        except json.JSONDecodeError as exc:
            # An incomplete response is not an executable decision. Never
            # repair guessed syntax or expose response snippets in stderr.
            raise AgentParseError(
                f"agent output must be one complete JSON object (line {exc.lineno}, column {exc.colno})"
            ) from None
        except ValueError:
            raise AgentParseError("agent output must be one unambiguous JSON object") from None
        if not isinstance(payload, dict):
            raise AgentParseError("agent output must be a JSON object")
        return payload
