from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping, Sequence

from pydantic import Field, model_validator

from sitina.constants import SITINA_HOME
from sitina.conversation.models import ChatMode
from sitina.schemas.models import StrictModel
from sitina.utils import sha256_text, stable_json


class RoutingSliceMetrics(StrictModel):
    total: int = Field(ge=0)
    accurate: int = Field(ge=0)
    accuracy_ppm: int = Field(ge=0, le=1_000_000)
    false_upgrade_count: int = Field(ge=0)
    false_downgrade_count: int = Field(ge=0)
    dangerous_false_downgrade_count: int = Field(ge=0)


class RoutingEvaluationReport(StrictModel):
    schema_id: Literal["SITINA_ROUTING_EVALUATION_V1"] = Field(default="SITINA_ROUTING_EVALUATION_V1", alias="schema")
    fixture_version: str
    policy_version: str
    overall: RoutingSliceMetrics
    language_slices: dict[str, RoutingSliceMetrics]
    domain_slices: dict[str, RoutingSliceMetrics]


class RoutingEvaluationSuite:
    @staticmethod
    def _metrics(rows: Sequence[Mapping[str, Any]]) -> RoutingSliceMetrics:
        total = len(rows)
        accurate = sum(item["actual"] == item["expected"] for item in rows)
        false_upgrades = sum(item["actual"] == "MULTI" and item["expected"] == "FAST" for item in rows)
        false_downgrades = sum(item["actual"] == "FAST" and item["expected"] == "MULTI" for item in rows)
        dangerous = sum(
            item["actual"] == "FAST"
            and item["expected"] == "MULTI"
            and item["risk"] in {"high", "critical"}
            for item in rows
        )
        return RoutingSliceMetrics(
            total=total,
            accurate=accurate,
            accuracy_ppm=accurate * 1_000_000 // total if total else 0,
            false_upgrade_count=false_upgrades,
            false_downgrade_count=false_downgrades,
            dangerous_false_downgrade_count=dangerous,
        )

    def evaluate(self, router: Any, document: Mapping[str, Any], *, snapshot: Any) -> RoutingEvaluationReport:
        if document.get("schema") != "SITINA_ROUTING_REGRESSION_FIXTURES_V1":
            raise ValueError("routing evaluation fixture schema mismatch")
        fixtures = document.get("fixtures")
        if not isinstance(fixtures, list) or not fixtures:
            raise ValueError("routing evaluation fixtures are empty")
        rows: list[dict[str, str]] = []
        for fixture in fixtures:
            required = {"id", "language", "domain", "risk", "message", "expected_route", "allowed_routes", "reason_code"}
            if not isinstance(fixture, dict) or not required.issubset(fixture):
                raise ValueError("routing evaluation fixture is incomplete")
            decision = router.decide(ChatMode.AUTO, str(fixture["message"]), snapshot)
            actual = decision.resolved_mode.value
            allowed = {str(item) for item in fixture["allowed_routes"]}
            evidence_codes = set(dict(decision.observability or {}).get("evidence_codes") or ())
            if actual not in allowed or str(fixture["reason_code"]) not in evidence_codes:
                actual = "INVALID"
            rows.append(
                {
                    "actual": actual,
                    "expected": str(fixture["expected_route"]),
                    "language": str(fixture["language"]),
                    "domain": str(fixture["domain"]),
                    "risk": str(fixture["risk"]),
                }
            )

        def slices(field: str) -> dict[str, RoutingSliceMetrics]:
            grouped: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
            for row in rows:
                grouped[row[field]].append(row)
            return {key: self._metrics(grouped[key]) for key in sorted(grouped)}

        return RoutingEvaluationReport(
            fixture_version=str(document["fixture_version"]),
            policy_version=str(getattr(router, "policy_version", document.get("policy_version", "unknown"))),
            overall=self._metrics(rows),
            language_slices=slices("language"),
            domain_slices=slices("domain"),
        )


class ExecutableSuiteCase(StrictModel):
    component: str
    test_id: str
    proves: str


class ExecutableSuiteContract(StrictModel):
    schema_id: Literal["SITINA_EXECUTABLE_SUITE_CONTRACT_V1"] = Field(default="SITINA_EXECUTABLE_SUITE_CONTRACT_V1", alias="schema")
    suite: Literal["collaboration", "concurrency", "chaos", "performance"]
    required_components: tuple[str, ...]
    cases: tuple[ExecutableSuiteCase, ...]

    @model_validator(mode="after")
    def exact_coverage(self) -> "ExecutableSuiteContract":
        components = tuple(sorted(item.component for item in self.cases))
        if components != tuple(sorted(self.required_components)) or len(components) != len(set(components)):
            raise ValueError("executable suite component coverage is incomplete or duplicated")
        if any(not item.test_id.startswith("tests.") or not item.proves.strip() for item in self.cases):
            raise ValueError("executable suite cases require test IDs and assertion explanations")
        return self


EvaluationStatus = Literal["pass", "fail", "insufficient_evidence"]


class EvaluationDimension(StrictModel):
    status: EvaluationStatus
    score: int = Field(ge=0, le=100)
    reason_codes: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    evaluator_version: str


class RunEvaluation(StrictModel):
    schema_id: Literal["SITINA_RUN_EVALUATION_V1"] = Field(default="SITINA_RUN_EVALUATION_V1", alias="schema")
    run_id: str
    tool_correctness: EvaluationDimension
    state_correctness: EvaluationDimension
    permission_compliance: EvaluationDimension
    cost_efficiency: EvaluationDimension
    recovery_ability: EvaluationDimension
    final_quality: EvaluationDimension
    evaluator_version: str
    source: Literal["run_ledger"] = "run_ledger"
    read_only: Literal[True] = True
    evaluation_hash: str


def sign_evaluation_event(event: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(event)
    value.pop("evidence_hash", None)
    value["evidence_hash"] = sha256_text(stable_json(value))
    return value


class RunEvaluator:
    VERSION = "run-evaluator-1.0"

    def __init__(self, home: Path = SITINA_HOME):
        self.home = Path(home)

    def _timeline(self, run_id: str) -> list[dict[str, Any]]:
        production_genesis = self.home / "state/bplus-production-genesis/genesis.json"
        clean_genesis = self.home / "state/clean-acceptance/genesis.json"
        if clean_genesis.is_file():
            from sitina.orchestrator.clean_acceptance import CleanAcceptanceContext

            return list(CleanAcceptanceContext.load(self.home).trace_run(run_id).get("timeline", []))
        if production_genesis.is_file():
            from sitina.orchestrator.bplus_production import ProductionRuntimeContext

            context = ProductionRuntimeContext.load(
                self.home,
                allow_simulation=(self.home / ".sitina-bplus-disposable-v1").is_file(),
            )
            return list(context.trace_run(run_id).get("timeline", []))
        db_path = self.home / "data/sitina.db"
        if not db_path.is_file():
            return []
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as connection:
            rows = connection.execute(
                "SELECT id,ts,trace_id,payload_json FROM events WHERE run_id=? AND event_type='run_ledger' ORDER BY id ASC",
                (run_id,),
            ).fetchall()
        timeline = []
        for row_id, timestamp, trace_id, payload_json in rows:
            payload = json.loads(payload_json)
            payload.update({"_event_row_id": row_id, "_recorded_ts": timestamp, "_trace_id": trace_id})
            timeline.append(payload)
        return timeline

    @staticmethod
    def _integrity(event: Mapping[str, Any]) -> bool:
        if event.get("integrity_valid") is False:
            return False
        evidence_hash = event.get("evidence_hash")
        if evidence_hash is None:
            return True
        value = dict(event)
        value.pop("evidence_hash", None)
        return evidence_hash == sha256_text(stable_json(value))

    @staticmethod
    def _type(event: Mapping[str, Any]) -> str:
        return str(event.get("event_type") or "")

    @staticmethod
    def _payload(event: Mapping[str, Any]) -> Mapping[str, Any]:
        value = event.get("payload_json")
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _refs(events: Iterable[Mapping[str, Any]]) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    str(item.get("event_id") or item.get("event_hash") or item.get("evidence_hash"))
                    for item in events
                    if item.get("event_id") or item.get("event_hash") or item.get("evidence_hash")
                }
            )
        )

    def _dimension(
        self,
        *,
        evidence: Sequence[Mapping[str, Any]],
        passed: bool | None,
        pass_code: str,
        fail_code: str,
    ) -> EvaluationDimension:
        if passed is None or not evidence:
            return EvaluationDimension(
                status="insufficient_evidence",
                score=20,
                reason_codes=("EVIDENCE_MISSING",),
                evidence_refs=self._refs(evidence),
                evaluator_version=self.VERSION,
            )
        return EvaluationDimension(
            status="pass" if passed else "fail",
            score=100 if passed else 0,
            reason_codes=(pass_code if passed else fail_code,),
            evidence_refs=self._refs(evidence),
            evaluator_version=self.VERSION,
        )

    def evaluate(self, run_id: str, *, events: Sequence[Mapping[str, Any]] | None = None) -> RunEvaluation:
        source = tuple(dict(item) for item in (events if events is not None else self._timeline(run_id)))
        scoped = tuple(item for item in source if (item.get("run_id") or self._payload(item).get("run_id")) == run_id)
        invalid = tuple(item for item in scoped if not self._integrity(item))
        valid = tuple(item for item in scoped if self._integrity(item))

        tools = tuple(item for item in valid if "tool" in self._type(item))
        tool_pass = None if not tools else not any(
            (item.get("status") or self._payload(item).get("status")) in {"failed", "error", "blocked"}
            for item in tools
        )
        terminals = tuple(item for item in valid if self._type(item) in {"run_completed", "run_failed", "run_blocked", "run_cancelled", "run_timeout"})
        transitions = tuple(item for item in valid if self._type(item) in {"task_graph_node_status", "state_transition"})
        states = transitions + terminals
        state_pass = None if not transitions or not terminals else len(terminals) == 1 and self._type(terminals[0]) == "run_completed"
        permissions = tuple(item for item in valid if self._type(item) in {"permission_decision", "approval_decision"})
        permission_pass = None if not permissions else all(
            (item.get("status") or self._payload(item).get("status")) not in {"denied", "failed", "blocked"}
            and self._payload(item).get("allowed", True) is True
            for item in permissions
        )
        costs = tuple(item for item in valid if self._type(item).startswith("provider_http_attempt") or "budget" in self._type(item))
        usage_values = [self._payload(item).get("token_usage") for item in costs if self._type(item).startswith("provider_http_attempt")]
        reservations = [
            int(self._payload(item).get("reserved_tokens", 0) or 0)
            for item in costs
            if self._type(item) == "token_budget_reserved"
        ]
        usage_complete = bool(usage_values) and all(isinstance(item, dict) and "total_tokens" in item for item in usage_values)
        used_tokens = sum(int(item.get("total_tokens", 0)) for item in usage_values if isinstance(item, dict))
        cost_pass = None if not costs or not usage_values or not reservations else usage_complete and used_tokens <= sum(reservations)
        failures = tuple(item for item in valid if any(word in self._type(item) for word in ("failed", "timeout", "crash")))
        recoveries = tuple(item for item in valid if self._type(item) in {"retry_succeeded", "checkpoint_resumed", "worker_recovered"})
        recovery_not_required = tuple(item for item in valid if self._type(item) == "recovery_not_required")
        recovery_evidence = failures + recoveries if failures else recovery_not_required
        recovery_pass = (bool(recoveries) if failures else bool(recovery_not_required)) if recovery_evidence else None
        quality = tuple(item for item in valid if self._type(item) in {"reviewer_decision", "evaluation_completed"}) + terminals
        reviewer_accept = any(
            self._payload(item).get("decision") in {"accept", "accepted", "pass"}
            for item in quality
            if self._type(item) == "reviewer_decision"
        )
        quality_pass = None if not quality or not terminals else reviewer_accept and self._type(terminals[0]) == "run_completed"

        dimensions = {
            "tool_correctness": self._dimension(evidence=tools, passed=tool_pass, pass_code="TOOLS_SUCCEEDED", fail_code="TOOL_FAILURE"),
            "state_correctness": self._dimension(evidence=states, passed=state_pass, pass_code="STATE_TERMINAL_VALID", fail_code="STATE_TERMINAL_INVALID"),
            "permission_compliance": self._dimension(evidence=permissions, passed=permission_pass, pass_code="PERMISSIONS_COMPLIANT", fail_code="PERMISSION_VIOLATION"),
            "cost_efficiency": self._dimension(evidence=costs, passed=cost_pass, pass_code="USAGE_SETTLED", fail_code="USAGE_UNSETTLED"),
            "recovery_ability": self._dimension(evidence=recovery_evidence, passed=recovery_pass, pass_code="RECOVERY_VERIFIED", fail_code="RECOVERY_FAILED"),
            "final_quality": self._dimension(evidence=quality, passed=quality_pass, pass_code="FINAL_ACCEPTED", fail_code="FINAL_REJECTED"),
        }
        if invalid:
            invalid_refs = self._refs(invalid)
            dimensions = {
                name: value.model_copy(
                    update={
                        "status": "fail",
                        "score": min(value.score, 20),
                        "reason_codes": tuple(sorted(set(value.reason_codes + ("EVIDENCE_INTEGRITY_INVALID",)))),
                        "evidence_refs": tuple(sorted(set(value.evidence_refs + invalid_refs))),
                    }
                )
                for name, value in dimensions.items()
            }
        unsigned = {
            "run_id": run_id,
            **{name: value.model_dump() for name, value in dimensions.items()},
            "evaluator_version": self.VERSION,
            "source": "run_ledger",
            "read_only": True,
        }
        return RunEvaluation(**unsigned, evaluation_hash=sha256_text(stable_json(unsigned)))


__all__ = [
    "ExecutableSuiteCase",
    "ExecutableSuiteContract",
    "RoutingEvaluationSuite",
    "RunEvaluator",
    "sign_evaluation_event",
]
