from __future__ import annotations

from pathlib import Path

from sitina.constants import RISK_ORDER, SITINA_HOME
from sitina.schemas.models import MandatorySteps, RunState
from sitina.storage import SitinaStore
from sitina.utils import new_id, write_json


class RunStateManager:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)

    def create(self, risk_level: str = "critical") -> RunState:
        state = RunState(
            run_id=new_id(),
            phase="created",
            risk_level=risk_level,  # type: ignore[arg-type]
            approval_required=RISK_ORDER.get(risk_level, 3) >= RISK_ORDER["high"],
            mandatory_steps=self.mandatory_steps_for_risk(risk_level),
        )
        self.save(state)
        return state

    def mandatory_steps_for_risk(self, risk_level: str) -> MandatorySteps:
        if risk_level in {"critical"}:
            return MandatorySteps(tester_required=True, reviewer_required=True, architect_required=True)
        if risk_level in {"high"}:
            return MandatorySteps(tester_required=True, reviewer_required=True, architect_required=False)
        if risk_level in {"medium"}:
            return MandatorySteps(tester_required=True, reviewer_required=True, architect_required=False)
        return MandatorySteps(tester_required=False, reviewer_required=False, architect_required=False)

    def transition(self, state: RunState, phase: str, active_agent: str | None = None) -> RunState:
        updated = state.model_copy(update={"phase": phase, "active_agent": active_agent, "updated_by": "harness"})
        self.save(updated)
        return updated

    def mark_dirty(self, state: RunState, reason: str) -> RunState:
        updated = state.model_copy(update={"phase": "interrupted", "verification_status": "not_verified", "updated_by": "harness"})
        self.store.record_event("dirty_state", {"reason": reason}, run_id=state.run_id)
        self.save(updated)
        return updated

    def save(self, state: RunState) -> None:
        write_json(self.home / "state" / "run_state.json", state.model_dump())
        self.store.upsert_run_state(state.model_dump())
        self.store.record_event("run_state", state.model_dump(), run_id=state.run_id)
