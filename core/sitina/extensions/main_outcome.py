"""Explicit business-turn completion; clarification keeps its native contract.

An answer is a candidate for verification, never an approval.  Keeping this
transport envelope separate prevents free-form questions from silently taking
the completion path.  It does not infer user intent from language or keywords.
"""
from sitina.runners.provider import parse_complete_json_object


MAIN_OUTCOME_INSTRUCTION = (
    "\nFor a business turn with no tool calls, choose one explicit outcome. "
    "If a genuinely unavailable user input blocks further authorized work, use "
    "the existing goal_input object with missing_inputs and a concrete question; "
    "preserve the current goal, constraints and all acceptance conditions. "
    "Do not put that question in a completion candidate. If the authorized work "
    "is ready for verification, return exactly {\"completion_candidate\":\"the complete user-facing answer\"}. "
    "The answer string must preserve the user's requested format and content. "
    "This submits work to existing verification; it does not approve it. "
    "Do not return bare prose, Markdown around the JSON, or both outcome keys. "
    "Tool-use turns keep their existing protocol. Internal errors are not missing "
    "user input; never invent a question or a user decision to escape them."
)


def main_completion_candidate(text: str) -> str:
    """Validate one final outcome and return only its original answer bytes."""
    document = parse_complete_json_object(text)
    if set(document) != {"completion_candidate"}:
        raise ValueError("main final response requires completion_candidate or the existing goal_input decision")
    answer = document["completion_candidate"]
    if not isinstance(answer, str) or not answer.strip():
        raise ValueError("completion_candidate must be a nonempty answer string")
    return answer
