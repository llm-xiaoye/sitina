from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from sitina.schemas.models import CommonAgentOutput, validate_agent_output


class AgentParseError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedAgentOutput:
    output: CommonAgentOutput
    payload: dict[str, Any]


class AgentOutputParser:
    def parse(self, agent: str, text: str) -> ParsedAgentOutput:
        payload = self.parse_single_json(text)
        try:
            output = validate_agent_output(agent, payload)
        except ValidationError as exc:
            raise AgentParseError(f"{agent} output schema_error: {exc}") from exc
        except ValueError as exc:
            raise AgentParseError(f"{agent} output schema_error: {exc}") from exc
        return ParsedAgentOutput(output=output, payload=output.model_dump())

    def parse_single_json(self, text: str) -> dict[str, Any]:
        stripped = text.strip()
        fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", stripped, flags=re.DOTALL)
        if fenced:
            stripped = fenced.group(1).strip()
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise AgentParseError(f"agent output must be one JSON object: {exc}") from exc
        if not isinstance(payload, dict):
            raise AgentParseError("agent output must be a JSON object")
        return payload
