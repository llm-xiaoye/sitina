from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from sitina.journal.model import validate_identifier


class ClosingPermitError(RuntimeError):
    pass


class ClosingEffectPurpose(str, Enum):
    RECONCILIATION = "RECONCILIATION"
    COMPENSATION = "COMPENSATION"
    DISCLOSURE = "DISCLOSURE"
    CONTAINMENT = "CONTAINMENT"
    MONITORING = "MONITORING"


@dataclass(frozen=True)
class ClosingPermit:
    permit_id: str
    run_id: str
    linked_effect_ids: frozenset[str]
    max_depth: int
    purposes: frozenset[ClosingEffectPurpose]

    def __post_init__(self) -> None:
        validate_identifier(self.permit_id, field="permit_id")
        validate_identifier(self.run_id, field="run_id")
        if not self.linked_effect_ids or self.max_depth < 1 or not self.purposes:
            raise ValueError("Closing Permit scope, depth, and purpose are required")

    def authorize(self, *, effect_id: str, linked_effect_id: str, purpose: ClosingEffectPurpose | str, depth: int) -> dict[str, object]:
        try:
            resolved = purpose if isinstance(purpose, ClosingEffectPurpose) else ClosingEffectPurpose(purpose)
        except ValueError as error:
            raise ClosingPermitError("ordinary Effect expansion is forbidden during Closing") from error
        if resolved not in self.purposes:
            raise ClosingPermitError("Closing Effect purpose is outside permit scope")
        if linked_effect_id not in self.linked_effect_ids:
            raise ClosingPermitError("Closing Effect is not linked to an admitted exposure")
        if depth < 1 or depth > self.max_depth:
            raise ClosingPermitError("Closing Effect depth exceeds permit")
        validate_identifier(effect_id, field="effect_id")
        return {
            "schema": "CLOSING_EFFECT_AUTHORIZED_V1",
            "permit_id": self.permit_id,
            "run_id": self.run_id,
            "effect_id": effect_id,
            "linked_effect_id": linked_effect_id,
            "purpose": resolved.value,
            "depth": depth,
        }
