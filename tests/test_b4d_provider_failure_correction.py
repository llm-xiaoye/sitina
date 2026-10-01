from __future__ import annotations

from pathlib import Path
import sys

import pytest
from types import SimpleNamespace

from sitina.cas.model import CASError
from sitina.extensions.manager import ExtensionManager
from sitina.extensions.runtime import AutonomousRuntime, BoundedToolTurnClient
from sitina.loop import LoopBackend
from sitina.loop.control import LoopAuthorityLease
from sitina.loop.model import EffectStatus, TaskStatus
from sitina.loop.task_runtime import (
    LoopOperationAdapter,
    LoopTaskRunner,
    ProviderFailureEvidenceUnavailable,
    _persisted_provider_failure,
)
from sitina.runners.provider import (
    ProviderError,
    ProviderHTTPError,
    ProviderProfile,
    ProviderToolCall,
    ScriptedMockToolClient,
)
from sitina.security.key_provider import KeyProviderError

from test_loop_batch_1b_runtime import boundary_fixture, reviewer_evidence_turn, turn


class _Keys:
    provider_id = "b4d-provider-failure-test"

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], bytes] = {}

    def get(self, service: str, account: str) -> bytes | None:
        return self.items.get((service, account))

    def put(self, service: str, account: str, value: bytes, *, replace: bool = False) -> None:
        key = (service, account)
        if key in self.items and not replace:
            raise KeyProviderError("already exists")
        self.items[key] = bytes(value)

    def public_inventory(self) -> dict[str, object]:
        return {"schema": "B4D_PROVIDER_FAILURE_TEST_KEYS", "secret_values_included": False}


def _run_failure(
    tmp_path: Path, dispatch, *, stop_blocker: str | None = None,
    expected_error: type[BaseException] = ProviderError,
):
    boundary = boundary_fixture(tmp_path)
    boundary.business_workspace.mkdir(parents=True, exist_ok=True)
    keys = _Keys()
    with LoopAuthorityLease(boundary.state_root):
        with LoopBackend.open(boundary.state_root, keychain_backend=keys) as backend:
            backend.create_task(
                task_id="provider-failure",
                session_id="provider-failure",
                task_kind="no_change",
                goal="observe Provider failure",
                required_outcome_ids=("outcome-1",),
                artifact_ref="artifact-provider-failure",
                environment_ref="environment-provider-failure",
                capability_snapshot_id="provider-failure",
            )
            adapter = LoopOperationAdapter(backend, "provider-failure", boundary.business_workspace)
            with pytest.raises(expected_error):
                adapter.provider_call("provider-run", 1, dispatch)
            task = backend.get_task("provider-failure")
            operation = task.operations[adapter.operation_ids[-1]]
            assert operation.result_ref
            result_document = backend.context_memory.read(str(operation.result_ref))
            report = None
            if stop_blocker is not None:
                waiting = backend.dock_waiting(
                    task.task_id,
                    status=TaskStatus.WAITING_INPUT,
                    blocker_id=stop_blocker,
                    reason="fixture stop classification",
                    evidence_refs=(str(operation.result_ref),),
                )
                report = backend.context_memory.read(str(waiting.stop_report_ref))
            return operation, dict(result_document["result"]), report


def _raise(error):
    def dispatch():
        raise error

    return dispatch


def test_native_http_failure_persists_known_status_and_exact_send(tmp_path: Path) -> None:
    profile = ProviderProfile("fixture", "https://api.example.invalid", "none", "fixture-model")

    class Client:
        def complete_tool_turn(self, _profile, **_kwargs):
            error = ProviderHTTPError(402, "secret response body must not persist")
            error.sitina_physical_send_count = 1
            error.sitina_physical_send_status = "response_received"
            raise error

    bounded = BoundedToolTurnClient(Client(), profile, backoff_seconds=0)
    operation, result, report = _run_failure(
        tmp_path,
        lambda: bounded.complete_tool_turn(profile, system_prompt="", messages=[], tools=[], max_tokens=1),
        stop_blocker="provider-http-failure",
    )
    assert operation.effect_status is EffectStatus.FAILED
    failure = result["provider_failure"]
    assert failure["failure_class"] == "known_http_failure"
    assert failure["http_status_code"] == 402
    assert failure["physical_send_count"] == 1
    assert failure["physical_send_count_status"] == "exact"
    assert failure["uncertain_physical_send_attempt_count"] == 0
    assert "secret response body" not in str(failure)
    assert result["business_effect_dispatched"] is False
    assert report is not None
    assert report["task_scope_metrics"]["provider_physical_send_count"] == 1
    assert report["task_scope_metrics"]["provider_physical_send_count_lower_bound"] == 1

    from sitina.runners.provider import ProviderRequiredOutputEmpty

    class EmptyClient:
        def __init__(self):
            self.calls = 0

        def complete_tool_turn(self, _profile, **_kwargs):
            self.calls += 1
            raise ProviderRequiredOutputEmpty({
                "required_output": "json_object_without_tools",
                "content_present": True, "content_type": "str", "content_utf8_bytes": 0,
                "finish_reason": "stop", "explicit_refusal": False,
                "physical_send_count": 1, "http_status_code": 200,
                "provider_request_id": f"request-{self.calls}",
                "token_usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
            })

    client = EmptyClient()
    bounded = BoundedToolTurnClient(client, profile, retry_limit=2, backoff_seconds=0)
    operation, result, report = _run_failure(
        tmp_path / "required-empty",
        lambda: bounded.complete_tool_turn(profile, system_prompt="", messages=[], tools=[], max_tokens=1),
        stop_blocker="provider-required-output-empty",
    )
    failure = result["provider_failure"]
    assert client.calls == 3
    assert operation.effect_status is EffectStatus.FAILED
    assert failure["failure_class"] == "required_output_empty"
    assert failure["http_status_code"] == 200
    assert failure["physical_send_count"] == 3
    assert failure["retry_count"] == 2
    assert failure["fallback_count"] == 0
    assert failure["usage_status"] == "known"
    assert failure["usage_unsettled"] is False
    assert failure["token_usage"] == {"input_tokens": 30, "output_tokens": 6, "total_tokens": 36}
    assert [item["provider_request_id"] for item in failure["provider_output_attempts"]] == [
        "request-1", "request-2", "request-3",
    ]
    assert result["metadata"]["provider_output_attempts"] == failure["provider_output_attempts"]
    assert report["task_scope_metrics"]["provider_physical_send_count"] == 3
    assert report["task_scope_metrics"]["provider_retry_count"] == 2
    assert report["task_scope_metrics"]["provider_input_tokens"] == 30
    assert report["task_scope_metrics"]["provider_output_tokens"] == 6
    assert report["task_scope_metrics"]["provider_token_total"] == 36
    assert report["task_scope_metrics"]["provider_metrics_complete"] is True


def test_native_unknown_preserves_uncertain_attempt_after_later_http_response(tmp_path: Path) -> None:
    profile = ProviderProfile("fixture", "https://api.example.invalid", "none", "fixture-model")

    class Client:
        def __init__(self):
            self.calls = 0

        def complete_tool_turn(self, _profile, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                raise ProviderError("provider worker exited without a result")
            error = ProviderHTTPError(402, "later HTTP response")
            error.sitina_physical_send_count = 1
            error.sitina_physical_send_status = "response_received"
            raise error

    bounded = BoundedToolTurnClient(Client(), profile, retry_limit=1, backoff_seconds=0)
    operation, result, report = _run_failure(
        tmp_path,
        lambda: bounded.complete_tool_turn(profile, system_prompt="", messages=[], tools=[], max_tokens=1),
        stop_blocker="provider-transport-unavailable",
    )
    assert operation.effect_status is EffectStatus.UNKNOWN
    failure = result["provider_failure"]
    assert failure["failure_class"] == "unknown_provider_failure"
    assert "http_status_code" not in failure
    assert failure["physical_send_count"] == 0
    assert failure["physical_send_count_status"] == "lower_bound_with_uncertain_attempts"
    assert failure["uncertain_physical_send_attempt_count"] == 1
    assert result["effect_requires_probe"] is True

    assert report is not None
    metrics = report["task_scope_metrics"]
    assert metrics["provider_physical_send_count"] is None
    assert metrics["provider_physical_send_count_lower_bound"] == 0
    assert metrics["provider_uncertain_physical_send_attempt_count"] == 1
    assert bounded.client.calls == 1
    assert failure["retry_count"] == 0
    assert failure["fallback_count"] == 0
    assert len(failure["provider_output_attempts"]) == 1
    assert failure["provider_output_attempts"][0]["retry_safety_basis"] == "NO_RETRY_UNKNOWN_EFFECT"


def test_native_missing_metadata_stays_unknown_and_explicit_pre_send_is_failed(tmp_path: Path) -> None:
    operation, result, _report = _run_failure(
        tmp_path / "missing",
        _raise(ProviderError("worker crashed before metadata")),
    )
    assert operation.effect_status is EffectStatus.UNKNOWN
    assert result["provider_failure"]["failure_class"] == "unknown_provider_failure"
    assert result["provider_failure"]["physical_send_count_status"] == "unknown"
    assert result["provider_failure"]["uncertain_physical_send_attempt_count"] is None

    error = ProviderError("request rejected before send")
    error.sitina_physical_send_count = 0
    error.sitina_physical_send_status = "pre_send_validation_rejected"
    error.sitina_physical_send_count_status = "exact"
    error.sitina_uncertain_physical_send_attempt_count = 0
    error.sitina_retry_count = 0
    error.sitina_fallback_count = 0
    operation, result, _report = _run_failure(tmp_path / "pre-send", _raise(error))
    assert operation.effect_status is EffectStatus.FAILED
    assert result["provider_failure"]["failure_class"] == "not_dispatched_failure"
    assert result["provider_failure"]["effect_dispatched"] is False
    assert result["business_effect_dispatched"] is False

    from sitina.legacy.fence import LegacyWriteDenied

    for name, error_type, count, count_status, uncertain, marker, expected in (
        ("authorization", LegacyWriteDenied, 0, "exact", 0,
         "pre_send_authorization_rejected", EffectStatus.FAILED),
        ("authorization-after-send", LegacyWriteDenied, 1, "exact", 0,
         "pre_send_authorization_rejected", EffectStatus.UNKNOWN),
        ("authorization-uncertain", LegacyWriteDenied, 0, "lower_bound_with_uncertain_attempts", 1,
         "pre_send_authorization_rejected", EffectStatus.UNKNOWN),
        ("authorization-missing-count", LegacyWriteDenied, None, "unknown", None,
         "pre_send_authorization_rejected", EffectStatus.UNKNOWN),
        ("authorization-untyped", ProviderError, 0, "exact", 0,
         "pre_send_authorization_rejected", EffectStatus.UNKNOWN),
        ("authorization-unmarked", LegacyWriteDenied, 0, "exact", 0,
         "unknown", EffectStatus.UNKNOWN),
    ):
        error = error_type("authorization boundary fixture")
        error.sitina_physical_send_count = count
        error.sitina_physical_send_status = marker
        error.sitina_physical_send_count_status = count_status
        error.sitina_uncertain_physical_send_attempt_count = uncertain
        error.sitina_retry_count = 0
        error.sitina_fallback_count = 0
        operation, result, _report = _run_failure(
            tmp_path / name, _raise(error), expected_error=error_type,
        )
        assert operation.effect_status is expected
        assert result["provider_failure"]["physical_send_status"] == marker
        if expected is EffectStatus.FAILED:
            assert result["effect_dispatched"] is False
            assert result["recovery_decision"] == "NO_EFFECT"
            assert operation.unknown_effect is False
        else:
            assert result["recovery_decision"] == "NO_RETRY"
            assert operation.unknown_effect is True


def test_runner_stop_reason_uses_persisted_known_http_classification(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    boundary.business_workspace.mkdir(parents=True, exist_ok=True)
    keys = _Keys()
    profile = ProviderProfile("fixture", "https://api.example.invalid", "none", "fixture-model")

    class Client:
        def complete_tool_turn(self, _profile, **_kwargs):
            error = ProviderHTTPError(402, "balance unavailable")
            error.sitina_physical_send_count = 1
            error.sitina_physical_send_status = "response_received"
            raise error

    bounded = BoundedToolTurnClient(Client(), profile, backoff_seconds=0)

    class FailureRuntime:
        catalog = None
        max_turns = None
        no_provider_fixture = True

        def __init__(self, adapter):
            self.adapter = adapter

        def run(self, _prompt, **_kwargs):
            self.adapter.provider_call(
                "runner-provider",
                1,
                lambda: bounded.complete_tool_turn(
                    profile, system_prompt="", messages=[], tools=[], max_tokens=1
                ),
            )

    runner = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=lambda _role, adapter: FailureRuntime(adapter),  # type: ignore[arg-type]
    )
    result = runner.run(
        task_id="runner-http-failure",
        task_kind="readonly",
        goal="observe Provider refusal",
    )
    assert result["status"] == "waiting_input"
    assert result["blocker_id"] == "provider-http-failure"
    assert "HTTP status 402" in result["reason"]
    assert "retries exhausted" not in result["reason"]

    from sitina.runners.provider import ProviderRequiredOutputEmpty

    class EmptyClient:
        def complete_tool_turn(self, _profile, **_kwargs):
            raise ProviderRequiredOutputEmpty({
                "required_output": "json_object_without_tools",
                "physical_send_count": 1, "http_status_code": 200,
                "token_usage": {"input_tokens": 10, "output_tokens": 2, "total_tokens": 12},
            })

    boundary = boundary_fixture(tmp_path / "required-empty")
    boundary.business_workspace.mkdir(parents=True, exist_ok=True)
    keys = _Keys()
    bounded = BoundedToolTurnClient(EmptyClient(), profile, retry_limit=2, backoff_seconds=0)
    runner = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=lambda _role, adapter: FailureRuntime(adapter),  # type: ignore[arg-type]
    )
    result = runner.run(
        task_id="runner-required-empty", task_kind="readonly", goal="observe required empty output",
    )
    assert result["status"] == "waiting_input"
    assert result["blocker_id"] == "provider-required-output-empty"
    assert "bounded retries exhausted" in result["reason"]
    assert "HTTP status" not in result["reason"]


def test_runner_stop_reason_keeps_missing_provider_evidence_unknown(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    boundary.business_workspace.mkdir(parents=True, exist_ok=True)
    keys = _Keys()
    error = ProviderError("worker crashed before a result")

    class FailureRuntime:
        catalog = None
        max_turns = None
        no_provider_fixture = True

        def __init__(self, adapter):
            self.adapter = adapter

        def run(self, _prompt, **_kwargs):
            self.adapter.provider_call("runner-provider", 1, _raise(error))

    runner = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=lambda _role, adapter: FailureRuntime(adapter),  # type: ignore[arg-type]
    )
    result = runner.run(
        task_id="runner-unknown-failure",
        task_kind="readonly",
        goal="observe unknown Provider failure",
    )
    assert result["status"] == "waiting_input"
    assert result["blocker_id"] == "provider-transport-unavailable"
    assert "outcome is unknown" in result["reason"]


def test_provider_failure_cas_read_error_is_not_rewritten_as_observation() -> None:
    class BrokenMemory:
        def read(self, _reference):
            raise CASError("CAS authentication failed")

    backend = SimpleNamespace(context_memory=BrokenMemory())
    task = SimpleNamespace(
        operations={
            "provider-1": SimpleNamespace(result_ref="cas:provider-result"),
        }
    )
    with pytest.raises(ProviderFailureEvidenceUnavailable) as raised:
        _persisted_provider_failure(backend, task, ("provider-1",))
    assert raised.value.operation_id == "provider-1"
    assert raised.value.result_ref == "cas:provider-result"
    assert isinstance(raised.value.__cause__, CASError)


def test_reviewer_repair_uses_persisted_http_classification(tmp_path: Path) -> None:
    import json

    boundary = boundary_fixture(tmp_path)
    boundary.business_workspace.mkdir(parents=True, exist_ok=True)
    keys = _Keys()
    reviewer_clients = []

    class RepairReviewClient(ScriptedMockToolClient):
        def __init__(self, *, repair: bool):
            super().__init__([])
            self.repair = repair
            self.evidence_sent = False

        def complete_tool_turn(self, _profile, *, messages, **_kwargs):
            if not self.evidence_sent:
                self.evidence_sent = True
                return reviewer_evidence_turn(messages, call_prefix="repair-provider-proof")
            if not self.repair:
                return turn("{}")
            error = ProviderHTTPError(402, "reviewer repair balance refusal")
            error.sitina_physical_send_count = 1
            error.sitina_physical_send_status = "response_received"
            error.sitina_physical_send_count_status = "exact"
            error.sitina_uncertain_physical_send_attempt_count = 0
            error.sitina_retry_count = 0
            error.sitina_fallback_count = 0
            raise error

    def factory(role: str, _adapter):
        if _adapter.work_purpose == "goal_interpretation":
            client = ScriptedMockToolClient([turn(json.dumps({"goal_input": {
                "goal": "create result.txt",
                "constraints": [],
                "acceptance_conditions": ["result.txt contains ok"],
                "missing_inputs": [],
                "question": None,
            }}))])
        elif role == "main":
            client = ScriptedMockToolClient([
                turn("", ProviderToolCall(
                    "write-result",
                    "sitina_write_file",
                    {"path": "result.txt", "content": "ok"},
                )),
                turn("implemented"),
            ])
        else:
            client = RepairReviewClient(repair=bool(reviewer_clients))
            reviewer_clients.append(client)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            approval_callback=lambda _request: role == "main",
            workspace=boundary.business_workspace,
            max_turns=None,
            enforce_write_boundary=True,
            strict_workspace=True,
        )

    runner = LoopTaskRunner(
        boundary,
        approve_writes=True,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
    )
    result = runner.run(
        task_id="reviewer-repair-http-failure",
        task_kind="code_change",
        goal="create result.txt",
        check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('result.txt').read_text() == 'ok'"),
    )
    assert result["status"] == "waiting_input"
    assert result["blocker_id"] == "provider-http-failure"
    assert "Reviewer repair Provider returned HTTP status 402" in result["reason"]
    assert len(reviewer_clients) == 2
