from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from sitina.journal.model import validate_identifier


class BudgetError(RuntimeError):
    pass


class ReservationState(str, Enum):
    PENDING = "PENDING"
    ACTIVATED = "ACTIVATED"
    RELEASED = "RELEASED"
    LEAKED = "LEAKED"


@dataclass(frozen=True)
class BudgetReservation:
    budget_kind: str
    amount: int
    expires_at: int
    state: ReservationState = ReservationState.PENDING
    actual: int = 0

    def __post_init__(self) -> None:
        validate_identifier(self.budget_kind, field="budget_kind")
        if self.amount < 0:
            raise ValueError("budget reservation amount cannot be negative")


@dataclass(frozen=True)
class BudgetBundle:
    bundle_id: str
    effect_id: str
    effect_attempt_id: str
    fence: str
    reservations: tuple[BudgetReservation, ...]
    leak_obligation_open: bool = False
    blocks_ordinary_dispatch: bool = False

    @classmethod
    def create(cls, bundle_id: str, effect_id: str, effect_attempt_id: str, fence: str, reservations: tuple[BudgetReservation, ...]) -> "BudgetBundle":
        for value, field in ((bundle_id, "bundle_id"), (effect_id, "effect_id"), (effect_attempt_id, "effect_attempt_id"), (fence, "fence")):
            validate_identifier(value, field=field)
        if not reservations or len({item.budget_kind for item in reservations}) != len(reservations):
            raise BudgetError("Budget Bundle requires unique reservations")
        return cls(bundle_id, effect_id, effect_attempt_id, fence, reservations)

    def _index(self, budget_kind: str) -> int:
        try:
            return next(index for index, item in enumerate(self.reservations) if item.budget_kind == budget_kind)
        except StopIteration as error:
            raise BudgetError("unknown budget reservation") from error

    def activate(self, budget_kind: str) -> "BudgetBundle":
        index = self._index(budget_kind)
        current = self.reservations[index]
        reservations = list(self.reservations)
        reservations[index] = replace(current, state=ReservationState.ACTIVATED)
        return replace(self, reservations=tuple(reservations))

    def assert_dispatch_authorized(self, *, now: int, effect_id: str, effect_attempt_id: str, fence: str) -> None:
        if (effect_id, effect_attempt_id, fence) != (self.effect_id, self.effect_attempt_id, self.fence):
            raise BudgetError("Budget Bundle dispatch binding mismatch")
        if self.leak_obligation_open or self.blocks_ordinary_dispatch:
            raise BudgetError("Budget Bundle has an unresolved leak or debt")
        if any(item.state is not ReservationState.ACTIVATED or now > item.expires_at for item in self.reservations):
            raise BudgetError("all Budget Reservations must be active and unexpired")

    def fail_reservation(self, budget_kind: str, *, compensation_succeeds: bool) -> tuple["BudgetBundle", dict[str, Any]]:
        self._index(budget_kind)
        reservations = []
        leak = False
        for item in self.reservations:
            if item.state is ReservationState.ACTIVATED:
                state = ReservationState.RELEASED if compensation_succeeds else ReservationState.LEAKED
                leak = leak or state is ReservationState.LEAKED
                reservations.append(replace(item, state=state))
            else:
                reservations.append(item)
        updated = replace(self, reservations=tuple(reservations), leak_obligation_open=leak)
        schema = "BUDGET_RESERVATION_LEAK_OBLIGATION_V1" if leak else "BUDGET_BUNDLE_COMPENSATED_V1"
        return updated, {"schema": schema, "bundle_id": self.bundle_id, "failed_budget_kind": budget_kind, "leak_obligation_open": leak}

    def record_actual(self, budget_kind: str, actual: int) -> tuple["BudgetBundle", dict[str, Any]]:
        index = self._index(budget_kind)
        if actual < 0:
            raise BudgetError("actual cost cannot be negative")
        reservation = self.reservations[index]
        reservations = list(self.reservations)
        reservations[index] = replace(reservation, actual=actual)
        overrun = actual > reservation.amount
        updated = replace(self, reservations=tuple(reservations), blocks_ordinary_dispatch=self.blocks_ordinary_dispatch or overrun)
        return updated, {
            "schema": "BUDGET_OVERRUN_DEBT_V1" if overrun else "BUDGET_ACTUAL_RECORDED_V1",
            "bundle_id": self.bundle_id,
            "budget_kind": budget_kind,
            "reserved": reservation.amount,
            "actual": actual,
            "receipt_admitted": True,
        }
