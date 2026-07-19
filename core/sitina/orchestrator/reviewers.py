from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from sitina.constants import SITINA_HOME
from sitina.orchestrator.ledger import RunLedger
from sitina.schemas.models import StrictModel
from sitina.storage import SitinaStore
from sitina.utils import ensure_dir, iso_now, load_json_yaml, sha256_text, stable_json, write_json


ReviewScope = Literal["security", "code", "architecture", "test", "docs"]
ReviewDecisionValue = Literal["accept", "reject", "needs_changes", "advisory"]
ReviewSeverity = Literal["none", "minor", "major", "critical"]


class ReviewerRole(StrictModel):
    scope: list[ReviewScope]
    required_for_task_types: list[str]
    blocking_level: Literal["critical", "major", "minor", "advisory"]
    output_schema: Literal["reviewer_decision"]
    can_block: bool


class ReviewerDecision(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    reviewer_id: str
    scope: ReviewScope
    decision: ReviewDecisionValue
    severity: ReviewSeverity
    issues: list[dict[str, Any]] = Field(default_factory=list)
    patch_id: str
    patch_hash: str
    target_repo: str
    evidence: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_decision(self) -> "ReviewerDecision":
        if str(self.schema_version).split(".", 1)[0] != "1":
            raise ValueError("reviewer decision schema_version major must be 1")
        if self.decision == "accept" and self.severity in {"major", "critical"}:
            raise ValueError("reviewer cannot accept with major or critical severity")
        return self


class ReviewerMergeResult(StrictModel):
    schema_version: str = "1.0"
    run_id: str
    task_type: str
    patch_id: str
    patch_hash: str
    target_repo: str
    merged_decision: Literal["accept", "blocked", "needs_changes"]
    required_reviewers: list[str]
    received_reviewers: list[str]
    blocking_reviewers: list[str]
    advisory_reviewers: list[str]
    issues: list[dict[str, Any]]
    reason: str
    created_at: str


class MultiReviewer:
    def __init__(self, home: Path = SITINA_HOME, store: SitinaStore | None = None):
        self.home = home
        self.store = store or SitinaStore(home)
        self.path = home / "config" / "reviewers.yaml"
        self.config = load_json_yaml(self.path) if self.path.exists() else {}

    @property
    def roles(self) -> dict[str, ReviewerRole]:
        raw = self.config.get("reviewers", {})
        return {key: ReviewerRole.model_validate(value) for key, value in raw.items()}

    @property
    def merge_policy(self) -> dict[str, Any]:
        return self.config.get("review_merge_policy", {})

    def validate(self) -> tuple[list[str], list[str]]:
        errors: list[str] = []
        warnings: list[str] = []
        if not self.config:
            return ["reviewers config missing"], warnings
        if str(self.config.get("schema_version", "0")).split(".", 1)[0] != "1":
            errors.append("reviewers schema_version major must be 1")
        try:
            roles = self.roles
        except Exception as exc:  # noqa: BLE001
            return [f"reviewers config invalid: {exc}"], warnings
        for reviewer in ("security", "code", "architecture", "test", "docs"):
            if reviewer not in roles:
                errors.append(f"reviewer role missing: {reviewer}")
        policy = self.merge_policy
        for key in ("critical_blocks", "major_blocks", "needs_changes_blocks_apply", "advisory_does_not_block"):
            if key not in policy:
                errors.append(f"review_merge_policy missing {key}")
        if roles.get("docs") and roles["docs"].can_block:
            errors.append("docs reviewer must remain advisory/non-blocking")
        return errors, warnings

    def required_reviewers(self, task_type: str) -> list[str]:
        required = [reviewer_id for reviewer_id, role in self.roles.items() if task_type in role.required_for_task_types]
        return sorted(required)

    def merge(
        self,
        decisions: list[dict[str, Any] | ReviewerDecision],
        *,
        run_id: str,
        task_type: str,
        patch_id: str,
        patch_hash: str,
        target_repo: str,
    ) -> ReviewerMergeResult:
        parsed = [decision if isinstance(decision, ReviewerDecision) else ReviewerDecision.model_validate(decision) for decision in decisions]
        parsed = sorted(parsed, key=lambda item: item.reviewer_id)
        required = self.required_reviewers(task_type)
        received = [item.reviewer_id for item in parsed]
        missing = sorted(set(required) - set(received))
        blockers: list[str] = []
        advisory: list[str] = []
        issues: list[dict[str, Any]] = []
        reason_parts: list[str] = []
        if missing:
            blockers.extend(missing)
            reason_parts.append(f"missing required reviewer(s): {', '.join(missing)}")
        for item in parsed:
            if item.run_id != run_id:
                blockers.append(item.reviewer_id)
                reason_parts.append(f"{item.reviewer_id} run_id mismatch")
            if item.patch_id != patch_id or item.patch_hash != patch_hash:
                blockers.append(item.reviewer_id)
                reason_parts.append(f"{item.reviewer_id} patch binding mismatch")
            if item.target_repo != target_repo:
                blockers.append(item.reviewer_id)
                reason_parts.append(f"{item.reviewer_id} target_repo mismatch")
            role = self.roles.get(item.reviewer_id)
            if not role:
                blockers.append(item.reviewer_id)
                reason_parts.append(f"unknown reviewer role: {item.reviewer_id}")
                continue
            if item.decision == "advisory" or role.blocking_level == "advisory" or not role.can_block:
                advisory.append(item.reviewer_id)
            if item.decision == "reject":
                blockers.append(item.reviewer_id)
                reason_parts.append(f"{item.reviewer_id} rejected")
            if item.decision == "needs_changes" and self.merge_policy.get("needs_changes_blocks_apply", True):
                blockers.append(item.reviewer_id)
                reason_parts.append(f"{item.reviewer_id} needs changes")
            if item.severity == "critical" and self.merge_policy.get("critical_blocks", True):
                blockers.append(item.reviewer_id)
                reason_parts.append(f"{item.reviewer_id} critical severity")
            if item.severity == "major" and self.merge_policy.get("major_blocks", True):
                blockers.append(item.reviewer_id)
                reason_parts.append(f"{item.reviewer_id} major severity")
            issues.extend(item.issues)
        unique_blockers = sorted(set(blockers))
        merged_decision: Literal["accept", "blocked", "needs_changes"]
        if unique_blockers:
            merged_decision = "needs_changes" if any("needs changes" in part for part in reason_parts) else "blocked"
        else:
            merged_decision = "accept"
            reason_parts.append("all required reviewers accepted")
        result = ReviewerMergeResult(
            run_id=run_id,
            task_type=task_type,
            patch_id=patch_id,
            patch_hash=patch_hash,
            target_repo=target_repo,
            merged_decision=merged_decision,
            required_reviewers=required,
            received_reviewers=received,
            blocking_reviewers=unique_blockers,
            advisory_reviewers=sorted(set(advisory)),
            issues=issues,
            reason="; ".join(reason_parts),
            created_at=iso_now(),
        )
        self.record_merge(result)
        return result

    def record_merge(self, result: ReviewerMergeResult) -> None:
        payload = result.model_dump()
        RunLedger(self.home, self.store).record(
            "reviewer_decision",
            run_id=result.run_id,
            task_type=result.task_type,
            agent_id="reviewer",
            status="ok" if result.merged_decision == "accept" else "blocked",
            reason=result.reason,
            payload=payload,
        )
        self.store.record_audit(
            "reviewer_merge",
            payload,
            run_id=result.run_id,
            trace_id=f"{result.run_id}:reviewer_merge",
            agent="reviewer",
            exit_status=result.merged_decision,
            output_hash=sha256_text(stable_json(payload)),
        )

    def write_git_merge_artifact(self, patch_path: str | Path, result: ReviewerMergeResult) -> Path:
        patch = Path(patch_path).expanduser().resolve(strict=False)
        path = patch.with_name(patch.name + ".review.merge.json")
        ensure_dir(path.parent)
        write_json(path, result.model_dump())
        return path
