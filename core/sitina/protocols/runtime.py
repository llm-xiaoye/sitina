from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from sitina.journal.model import canonical_json_bytes, domain_hash, validate_identifier


class ProtocolTransitionRejected(RuntimeError):
    pass


@dataclass(frozen=True)
class Transition:
    name: str
    from_states: frozenset[str]
    to_state: str
    event_type: str
    timeout: bool = False

    def __post_init__(self) -> None:
        validate_identifier(self.name, field="transition_name")
        validate_identifier(self.to_state, field="to_state")
        validate_identifier(self.event_type, field="event_type")
        if not self.from_states:
            raise ValueError("transition requires at least one source state")
        for state in self.from_states:
            validate_identifier(state, field="from_state")

    def mapping(self) -> dict[str, Any]:
        return {"name": self.name, "from_states": sorted(self.from_states), "to_state": self.to_state, "event_type": self.event_type, "timeout": self.timeout}


@dataclass(frozen=True)
class ProtocolDefinition:
    protocol_id: str
    major: int
    initial_state: str
    terminal_states: frozenset[str]
    transitions: tuple[Transition, ...]
    policy_hash: str

    def __post_init__(self) -> None:
        validate_identifier(self.protocol_id, field="protocol_id")
        validate_identifier(self.initial_state, field="initial_state")
        if self.major != 1 or len(self.policy_hash) != 64:
            raise ValueError("invalid protocol major or policy hash")
        if len({transition.name for transition in self.transitions}) != len(self.transitions):
            raise ValueError("duplicate transition name")
        for state in self.terminal_states:
            validate_identifier(state, field="terminal_state")
        if self.initial_state in self.terminal_states:
            raise ValueError("initial state cannot be terminal")

    @property
    def definition_hash(self) -> str:
        return domain_hash(
            "PROTOCOL_DEFINITION",
            canonical_json_bytes(
                {
                    "protocol_id": self.protocol_id, "major": self.major, "initial_state": self.initial_state,
                    "terminal_states": sorted(self.terminal_states),
                    "transitions": [transition.mapping() for transition in self.transitions], "policy_hash": self.policy_hash,
                }
            ),
        )

    def transition(self, name: str) -> Transition:
        try:
            return next(transition for transition in self.transitions if transition.name == name)
        except StopIteration as error:
            raise ProtocolTransitionRejected(f"unknown transition: {name}") from error


@dataclass(frozen=True)
class ProtocolInstance:
    instance_id: str
    state: str
    definition_hash: str
    policy_hash: str
    generation: int
    applied_commands: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(cls, instance_id: str, definition: ProtocolDefinition) -> "ProtocolInstance":
        validate_identifier(instance_id, field="instance_id")
        return cls(instance_id, definition.initial_state, definition.definition_hash, definition.policy_hash, 0)


@dataclass(frozen=True)
class TransitionResult:
    instance: ProtocolInstance
    events: tuple[dict[str, Any], ...]
    duplicate: bool = False


def apply_transition(
    definition: ProtocolDefinition,
    instance: ProtocolInstance,
    transition_name: str,
    command_id: str,
    payload: Mapping[str, Any],
    *,
    timeout_fired: bool = False,
) -> TransitionResult:
    validate_identifier(command_id, field="command_id")
    if instance.definition_hash != definition.definition_hash or instance.policy_hash != definition.policy_hash:
        raise ProtocolTransitionRejected("instance definition/policy binding mismatch")
    request_hash = domain_hash(
        "PROTOCOL_TRANSITION_REQUEST",
        canonical_json_bytes({"instance_id": instance.instance_id, "transition": transition_name, "command_id": command_id, "payload": dict(payload), "timeout_fired": timeout_fired}),
    )
    prior = dict(instance.applied_commands).get(command_id)
    if prior is not None:
        if prior != request_hash:
            raise ProtocolTransitionRejected("same transition Command ID has a different request hash")
        return TransitionResult(instance, (), True)
    if instance.state in definition.terminal_states:
        raise ProtocolTransitionRejected("terminal protocol instance cannot transition")
    transition = definition.transition(transition_name)
    if instance.state not in transition.from_states:
        raise ProtocolTransitionRejected(f"transition {transition_name} is invalid from {instance.state}")
    if transition.timeout and not timeout_fired:
        raise ProtocolTransitionRejected("timeout transition requires a durable fired timer")
    if not transition.timeout and timeout_fired:
        raise ProtocolTransitionRejected("non-timeout transition cannot consume a timer firing")
    generation = instance.generation + 1
    event = {
        "schema": "PROTOCOL_TRANSITION_EVENT_V1", "protocol_id": definition.protocol_id,
        "instance_id": instance.instance_id, "definition_hash": definition.definition_hash,
        "policy_hash": definition.policy_hash, "command_id": command_id, "request_hash": request_hash,
        "transition": transition.name, "from_state": instance.state, "to_state": transition.to_state,
        "event_type": transition.event_type, "generation": generation, "payload": dict(payload),
    }
    updated = replace(
        instance,
        state=transition.to_state,
        generation=generation,
        applied_commands=instance.applied_commands + ((command_id, request_hash),),
    )
    return TransitionResult(updated, (event,))
