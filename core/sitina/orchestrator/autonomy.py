from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from sitina.constants import SITINA_HOME
from sitina.orchestrator.blackboard import Blackboard
from sitina.orchestrator.ledger import RunLedger
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import ensure_dir, iso_now, new_id, read_json, redact_text, sha256_text, stable_json, write_json


GoalStatus = Literal["active", "paused", "completed", "blocked"]
BacklogStatus = Literal["pending", "active", "in_progress", "blocked", "done", "rejected"]
BacklogRisk = Literal["low", "medium", "high", "critical"]


class Milestone(StrictModel):
    milestone_id: str
    title: str
    status: Literal["pending", "in_progress", "done"] = "pending"
    backlog_item_ids: list[str] = Field(default_factory=list)
    created_at: str
    updated_at: str | None = None


class LongTermGoal(StrictModel):
    schema_version: str = "1.0"
    goal_id: str
    title: str
    objective: str
    status: GoalStatus = "active"
    created_by: str = "cli"
    created_at: str
    updated_at: str | None = None
    backlog_item_ids: list[str] = Field(default_factory=list)
    run_ids: list[str] = Field(default_factory=list)


class BacklogItem(StrictModel):
    schema_version: str = "1.0"
    backlog_item_id: str
    goal_id: str | None = None
    title: str
    description: str
    status: BacklogStatus = "pending"
    priority: int = 3
    risk: BacklogRisk = "low"
    owner_agent: str = "controller"
    source_agent: str = "controller"
    source_run_id: str | None = None
    scope_refs: list[str] = Field(default_factory=list)
    linked_run_ids: list[str] = Field(default_factory=list)
    reviewer: str | None = None
    reviewed_at: str | None = None
    rejected_reason: str | None = None
    blocked_reason: str | None = None
    created_at: str
    updated_at: str | None = None


class ProjectPlan(StrictModel):
    schema_version: str = "1.0"
    goal_id: str
    milestone_ids: list[str] = Field(default_factory=list)
    backlog_item_ids: list[str] = Field(default_factory=list)
    updated_at: str


class AutonomyManager:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.path = home / "state" / "autonomy.json"
        self.ledger = RunLedger(home, self.store)
        self.blackboard = Blackboard(home, self.store)

    def validate(self) -> tuple[list[str], list[str]]:
        state = self._load()
        errors: list[str] = []
        for goal_id, goal in state.get("goals", {}).items():
            try:
                LongTermGoal.model_validate(goal)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"goal {goal_id} invalid: {exc}")
        for item_id, item in state.get("backlog", {}).items():
            try:
                BacklogItem.model_validate(item)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"backlog {item_id} invalid: {exc}")
        return errors, []

    def create_goal(self, title: str, objective: str, *, created_by: str = "cli") -> dict[str, Any]:
        state = self._load()
        goal = LongTermGoal(
            goal_id="goal_" + new_id(),
            title=self._safe(title, 160),
            objective=self._safe(objective, 2000),
            created_by=self._safe(created_by, 80),
            created_at=iso_now(),
        )
        state.setdefault("goals", {})[goal.goal_id] = goal.model_dump()
        state.setdefault("plans", {})[goal.goal_id] = ProjectPlan(goal_id=goal.goal_id, updated_at=iso_now()).model_dump()
        self._save(state)
        self._record("long_term_goal_created", goal.goal_id, goal.model_dump(), "long-term goal created")
        return {"status": "ok", "goal": goal.model_dump()}

    def list_goals(self) -> dict[str, Any]:
        state = self._load()
        goals = [LongTermGoal.model_validate(item).model_dump() for item in state.get("goals", {}).values()]
        goals.sort(key=lambda item: item["created_at"], reverse=True)
        return {"status": "ok", "goals": goals}

    def show_goal(self, goal_id: str) -> dict[str, Any]:
        state = self._load()
        goal = state.get("goals", {}).get(goal_id)
        if not goal:
            return {"status": "not_found", "goal_id": goal_id}
        plan = state.get("plans", {}).get(goal_id) or ProjectPlan(goal_id=goal_id, updated_at=iso_now()).model_dump()
        backlog = [item for item in state.get("backlog", {}).values() if item.get("goal_id") == goal_id]
        return {"status": "ok", "goal": goal, "plan": plan, "backlog": backlog}

    def update_goal_status(self, goal_id: str, status: GoalStatus, *, reviewer: str = "cli") -> dict[str, Any]:
        state = self._load()
        goal = state.get("goals", {}).get(goal_id)
        if not goal:
            return {"status": "not_found", "goal_id": goal_id}
        updated = LongTermGoal.model_validate(goal).model_copy(update={"status": status, "updated_at": iso_now()})
        state["goals"][goal_id] = updated.model_dump()
        self._save(state)
        self._record("long_term_goal_updated", goal_id, updated.model_dump() | {"reviewer": reviewer}, f"goal marked {status}")
        return {"status": "ok", "goal": updated.model_dump()}

    def create_backlog_candidate(
        self,
        *,
        title: str,
        description: str,
        goal_id: str | None = None,
        source_agent: str = "controller",
        source_run_id: str | None = None,
        priority: int = 3,
        risk: BacklogRisk = "low",
        scope_refs: list[str] | None = None,
    ) -> dict[str, Any]:
        state = self._load()
        if goal_id and goal_id not in state.get("goals", {}):
            return {"status": "not_found", "goal_id": goal_id}
        item = BacklogItem(
            backlog_item_id="backlog_" + new_id(),
            goal_id=goal_id,
            title=self._safe(title, 180),
            description=self._safe(description, 2000),
            priority=max(1, min(5, int(priority))),
            risk=risk,
            source_agent=self._safe(source_agent, 80),
            source_run_id=source_run_id,
            scope_refs=[self._safe(ref, 300) for ref in (scope_refs or [])],
            created_at=iso_now(),
        )
        state.setdefault("backlog", {})[item.backlog_item_id] = item.model_dump()
        if goal_id:
            goal = LongTermGoal.model_validate(state["goals"][goal_id])
            if item.backlog_item_id not in goal.backlog_item_ids:
                goal.backlog_item_ids.append(item.backlog_item_id)
            state["goals"][goal_id] = goal.model_copy(update={"updated_at": iso_now()}).model_dump()
            state.setdefault("plans", {}).setdefault(goal_id, ProjectPlan(goal_id=goal_id, updated_at=iso_now()).model_dump())
        self._save(state)
        run_id = source_run_id or item.backlog_item_id
        self.ledger.record(
            "backlog_candidate_created",
            run_id=run_id,
            task_type="chat",
            agent_id=source_agent,
            status="pending",
            reason="follow-up backlog candidate created; user approval required before activation",
            payload=item.model_dump(),
        )
        self.store.record_audit("backlog_candidate_created", item.model_dump(), run_id=run_id, agent=source_agent, exit_status="pending")
        if source_run_id:
            self.blackboard.record_document(
                run_id=source_run_id,
                task_id="main",
                author_agent=source_agent,
                doc_type="backlog_candidate",
                content_summary=f"{item.title}: {item.description}",
            )
        return {"status": "ok", "backlog_item": item.model_dump()}

    def propose_from_run(
        self,
        *,
        run_id: str,
        title: str,
        description: str,
        goal_id: str | None = None,
        source_agent: str = "goal_agent",
        priority: int = 3,
        risk: BacklogRisk = "low",
        scope_refs: list[str] | None = None,
    ) -> dict[str, Any]:
        result = self.create_backlog_candidate(
            title=title,
            description=description,
            goal_id=goal_id,
            source_agent=source_agent,
            source_run_id=run_id,
            priority=priority,
            risk=risk,
            scope_refs=scope_refs,
        )
        if result.get("status") != "ok":
            return result
        payload = {
            "run_id": run_id,
            "goal_id": goal_id,
            "source_agent": source_agent,
            "backlog_item_id": result["backlog_item"]["backlog_item_id"],
            "activation_policy": "review_accept_required_before_plan_activation",
        }
        self.ledger.record(
            "long_term_goal_agent_suggested",
            run_id=run_id,
            task_type="chat",
            agent_id=source_agent,
            status="pending",
            reason="long-term goal agent proposed backlog candidate; review required before plan activation",
            payload=payload,
        )
        self.store.record_audit("long_term_goal_agent_suggested", payload, run_id=run_id, agent=source_agent, exit_status="pending")
        self.blackboard.record_document(
            run_id=run_id,
            task_id="main",
            author_agent=source_agent,
            doc_type="backlog_candidate",
            content_summary=f"{result['backlog_item']['title']}: review required before plan activation",
        )
        return result

    def list_backlog(self, status: str | None = None, goal_id: str | None = None) -> dict[str, Any]:
        state = self._load()
        items = [BacklogItem.model_validate(item).model_dump() for item in state.get("backlog", {}).values()]
        if status and status != "all":
            items = [item for item in items if item["status"] == status]
        if goal_id:
            items = [item for item in items if item.get("goal_id") == goal_id]
        items.sort(key=lambda item: item["created_at"], reverse=True)
        return {"status": "ok", "backlog": items}

    def show_backlog(self, item_id: str) -> dict[str, Any]:
        item = self._load().get("backlog", {}).get(item_id)
        if not item:
            return {"status": "not_found", "backlog_item_id": item_id}
        return {"status": "ok", "backlog_item": item}

    def review_backlog(self, item_id: str, action: Literal["approve", "reject"], *, reviewer: str = "cli", reason: str | None = None) -> dict[str, Any]:
        state = self._load()
        raw = state.get("backlog", {}).get(item_id)
        if not raw:
            return {"status": "not_found", "backlog_item_id": item_id}
        item = BacklogItem.model_validate(raw)
        if item.status not in {"pending", "blocked"}:
            return {"status": "blocked", "reason": f"backlog item already {item.status}", "backlog_item": item.model_dump()}
        next_status: BacklogStatus = "active" if action == "approve" else "rejected"
        updated = item.model_copy(
            update={
                "status": next_status,
                "reviewer": self._safe(reviewer, 80),
                "reviewed_at": iso_now(),
                "rejected_reason": self._safe(reason or "Rejected by reviewer.", 500) if action == "reject" else None,
                "updated_at": iso_now(),
            }
        )
        state["backlog"][item_id] = updated.model_dump()
        if item.goal_id:
            plan = ProjectPlan.model_validate(state.setdefault("plans", {}).get(item.goal_id) or {"goal_id": item.goal_id, "updated_at": iso_now()})
            if action == "approve":
                plan_ids = list(dict.fromkeys([*plan.backlog_item_ids, item.backlog_item_id]))
            else:
                plan_ids = [existing for existing in plan.backlog_item_ids if existing != item.backlog_item_id]
            state["plans"][item.goal_id] = plan.model_copy(update={"backlog_item_ids": plan_ids, "updated_at": iso_now()}).model_dump()
        self._save(state)
        self._record("backlog_item_updated", item_id, updated.model_dump(), f"backlog item {action}d")
        return {"status": "ok", "backlog_item": updated.model_dump()}

    def link_run(self, run_id: str, *, goal_id: str | None = None, backlog_item_id: str | None = None) -> dict[str, Any]:
        if not goal_id and not backlog_item_id:
            return {"status": "ok", "linked": False}
        state = self._load()
        if goal_id and goal_id not in state.get("goals", {}):
            return {"status": "not_found", "goal_id": goal_id}
        if backlog_item_id and backlog_item_id not in state.get("backlog", {}):
            return {"status": "not_found", "backlog_item_id": backlog_item_id}
        if backlog_item_id:
            item = BacklogItem.model_validate(state["backlog"][backlog_item_id])
            if item.status != "active":
                reason = f"backlog item is {item.status} and has not been approved for a new run"
                payload = {
                    "run_id": run_id,
                    "goal_id": goal_id,
                    "backlog_item_id": backlog_item_id,
                    "backlog_status": item.status,
                    "reason": reason,
                }
                self.ledger.record(
                    "run_backlog_link_blocked",
                    run_id=run_id,
                    task_type="chat",
                    agent_id="controller",
                    status="blocked",
                    reason=reason,
                    payload=payload,
                )
                self.store.record_audit("run_backlog_link_blocked", payload, run_id=run_id, agent="controller", exit_status="blocked")
                return {"status": "blocked", **payload}
        if goal_id:
            goal = LongTermGoal.model_validate(state["goals"][goal_id])
            if run_id not in goal.run_ids:
                goal.run_ids.append(run_id)
            state["goals"][goal_id] = goal.model_copy(update={"updated_at": iso_now()}).model_dump()
        if backlog_item_id:
            item = BacklogItem.model_validate(state["backlog"][backlog_item_id])
            linked = list(dict.fromkeys([*item.linked_run_ids, run_id]))
            status: BacklogStatus = "in_progress" if item.status == "active" else item.status
            state["backlog"][backlog_item_id] = item.model_copy(update={"linked_run_ids": linked, "status": status, "updated_at": iso_now()}).model_dump()
        self._save(state)
        payload = {"run_id": run_id, "goal_id": goal_id, "backlog_item_id": backlog_item_id}
        self.ledger.record("run_backlog_linked", run_id=run_id, task_type="chat", agent_id="controller", reason="run linked to long-running goal/backlog", payload=payload)
        self.store.record_audit("run_backlog_linked", payload, run_id=run_id, agent="controller", exit_status="ok")
        return {"status": "ok", "linked": True, **payload}

    def update_backlog_from_run(self, run_id: str, run_status: str, *, reason: str | None = None) -> None:
        state = self._load()
        changed = False
        for item_id, raw in list(state.get("backlog", {}).items()):
            item = BacklogItem.model_validate(raw)
            if run_id not in item.linked_run_ids:
                continue
            if run_status == "blocked":
                item = item.model_copy(update={"status": "blocked", "blocked_reason": self._safe(reason or "linked run blocked", 500), "updated_at": iso_now()})
            elif run_status in {"done", "ok"}:
                item = item.model_copy(update={"status": "done", "updated_at": iso_now()})
            else:
                continue
            state["backlog"][item_id] = item.model_dump()
            self._record("backlog_item_updated", item_id, item.model_dump(), f"linked run updated backlog to {item.status}")
            changed = True
        if changed:
            self._save(state)

    def plan_show(self, goal_id: str) -> dict[str, Any]:
        state = self._load()
        if goal_id not in state.get("goals", {}):
            return {"status": "not_found", "goal_id": goal_id}
        plan = state.setdefault("plans", {}).get(goal_id) or ProjectPlan(goal_id=goal_id, updated_at=iso_now()).model_dump()
        milestones = [state.get("milestones", {}).get(item) for item in plan.get("milestone_ids", [])]
        backlog = [state.get("backlog", {}).get(item) for item in plan.get("backlog_item_ids", [])]
        return {"status": "ok", "goal_id": goal_id, "plan": plan, "milestones": [item for item in milestones if item], "backlog": [item for item in backlog if item]}

    def _record(self, event_type: str, run_id: str, payload: dict[str, Any], reason: str) -> None:
        self.ledger.record(event_type, run_id=run_id, task_type="chat", agent_id="controller", reason=reason, payload=payload)
        self.store.record_audit(event_type, payload, run_id=run_id, agent="controller", exit_status="ok")

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": "1.0", "goals": {}, "backlog": {}, "plans": {}, "milestones": {}}
        data = read_json(self.path)
        data.setdefault("schema_version", "1.0")
        data.setdefault("goals", {})
        data.setdefault("backlog", {})
        data.setdefault("plans", {})
        data.setdefault("milestones", {})
        return data

    def _save(self, state: dict[str, Any]) -> None:
        ensure_dir(self.path.parent)
        write_json(self.path, state)

    def _safe(self, value: str, limit: int) -> str:
        text = redact_text(str(value or "")).strip()
        return text[:limit] if text else "Untitled"
