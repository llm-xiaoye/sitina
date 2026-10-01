from __future__ import annotations

import json
import re
import socket
import time
import argparse
import sys
import threading
from pathlib import Path

import pytest

from sitina.extensions.manager import ExtensionManager
from sitina.extensions.runtime import AutonomousRuntime, AutonomousRuntimeError, GoalInputProtocolError
from sitina.loop import InputKind, LoopBackend
from sitina.loop.model import TaskConflict
from sitina.loop.control import LoopAuthorityLease, LoopControlAuthority, send_control_request
from sitina.loop.development import DevelopmentBoundary
from sitina.loop.task_runtime import (
    LoopOperationAdapter,
    LoopTaskRunner,
    LoopTaskRuntimeError,
    _structured_progress_advanced,
    _verified_history_read_source_refs,
    _workspace_snapshot,
)
from sitina.loop.termination import COUNT_NEUTRAL, COUNT_NO_PROGRESS, ReviewProtocolError
from sitina.loop.context_window import ContextCoreError, LoopRequestAssembler
from sitina.runners.provider import (
    ProviderProfile,
    ProviderToolCall,
    ProviderToolTurn,
    ScriptedMockToolClient,
)
from sitina.security.key_provider import KeyProviderError
from sitina.cli import cmd_loop_state


class MemoryKeychainBackend:
    provider_id = "memory-keychain-b1b"

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
        return {"schema": "MEMORY_KEYCHAIN_B1B", "secret_values_included": False}


def boundary_fixture(tmp_path: Path) -> DevelopmentBoundary:
    root = tmp_path / "dev"
    python = root / ".venv-r4/bin/python"
    python.parent.mkdir(parents=True)
    python.symlink_to(Path(sys.executable).resolve(strict=True))
    (root / "config").mkdir()
    source_config = Path(__file__).resolve().parents[1] / "config"
    for name in (
        "permissions.yaml",
        "roles.env",
        "sitina.yaml",
        "loop_context_capacity.json",
        "loop_context_capacity.provenance.json",
    ):
        source = source_config / name
        if source.exists():
            (root / "config" / name).write_bytes(source.read_bytes())
    capacity_path = root / "config/loop_context_capacity.json"
    capacity = json.loads(capacity_path.read_text(encoding="utf-8"))
    capacity["entries"].append({
        "profile": "mock",
        "endpoint": "mock://offline",
        "model": "scripted",
        "wire_protocol": "openai_chat_completions",
        "context_capacity_tokens": 1000000,
        "next_tool_turn_receipt_reserve_tokens": 8192,
        "history_query_max_bytes": 8192,
        "counter": {
            "mode": "conservative_utf8",
            "name": "offline-fixture-wire-bytes-v1",
            "applicability": "offline scripted test profile with no physical Provider send",
            "protocol_margin_tokens": 1024,
        },
    })
    capacity_path.write_text(json.dumps(capacity), encoding="utf-8")
    credential = tmp_path / "deepseek.env"
    credential.write_text("DEEPSEEK_API_KEY=fixture", encoding="utf-8")
    (root / "profiles").mkdir()
    (root / "profiles/deepseek.env").symlink_to(credential)
    (root / ".sitina-r4-development-root-v1.json").write_text(
        json.dumps({
            "schema": "SITINA_R4_DEVELOPMENT_ROOT_V1",
            "development_root": str(root),
            "runtime_relative_root": "runtime/r4-loop-dev",
            "state_authority_relative_root": "runtime/r4-loop-dev/state/task",
            "credential_references": [
                {"path": "profiles/deepseek.env", "access": "read_only_reference"}
            ],
            "forbidden_write_roots": [str(tmp_path / "forbidden")],
        }),
        encoding="utf-8",
    )
    return DevelopmentBoundary.validate(
        source_root=root,
        interpreter=python,
        state_root=root / "runtime/r4-loop-dev/state/task",
        business_workspace=root / "runtime/r4-loop-dev/workspaces/task",
        environment={"SITINA_HOME": str(root), "SITINA_R4_DEV_ROOT": str(root)},
    )


def turn(text: str = "", *calls: ProviderToolCall) -> ProviderToolTurn:
    return ProviderToolTurn(text, tuple(calls), "tool_calls" if calls else "stop", {"physical_send_count": 0})


def artifact_ref_from_messages(messages) -> str:
    match = re.search(r"Bound artifact ref:\n(\S+)", str(messages[-1]["content"]))
    if match:
        return match.group(1)
    context = json.loads(str(messages[0]["content"]))
    return str(context["execution_context"]["response_contract"]["artifact_ref"])


def reviewer_evidence_turn(messages, *, call_prefix: str) -> ProviderToolTurn:
    """Have legacy scripted reviewers satisfy the current proof-read contract."""

    context = json.loads(str(messages[0]["content"]))
    execution = context["execution_context"]
    candidates = [
        execution.get("artifact_source_ref"),
        execution.get("program_source_ref"),
        execution.get("main_result_source_ref"),
        *(execution.get("preflight_source_refs") or []),
    ]
    source_refs = tuple(dict.fromkeys(
        value for value in candidates if isinstance(value, str) and value.startswith("history:")
    ))
    assert source_refs
    return turn("", *(
        ProviderToolCall(
            f"{call_prefix}-{index}",
            "sitina_history_query",
            {"operation": "read", "source_ref": source_ref, "offset": 0, "max_bytes": 4096},
        )
        for index, source_ref in enumerate(source_refs, start=1)
    ))


def review_v2_document(messages, *, verdict: str, reason: str) -> dict[str, object]:
    context = json.loads(str(messages[0]["content"]))["execution_context"]
    contract = context["response_contract"]
    evidence_refs = list(dict.fromkeys(
        value
        for value in (
            context.get("artifact_source_ref"), context.get("program_source_ref"),
            context.get("main_result_source_ref"), *(context.get("preflight_source_refs") or ()),
        )
        if isinstance(value, str) and value
    ))
    business_request_refs = list(dict.fromkeys(
        reference
        for fact in context.get("business_evidence", {}).get("business_facts", ())
        for reference in (fact["source_ref"], fact.get("request_source_ref"))
        if reference
    ))
    inventory = list(contract.get("persisted_issue_inventory") or ())
    findings: list[dict[str, object]] = []
    if verdict == "PASS":
        for issue in inventory:
            findings.append({
                "stable_issue_id": issue["stable_issue_id"],
                "issue_slot_id": issue["issue_slot_id"],
                "rule_id": issue["rule_id"],
                "locus_id": issue["locus_id"],
                "object_id": issue["object_id"],
                "finding_code": issue["finding_code"],
                "disposition": "RESOLVED",
                "evidence_refs": evidence_refs,
                "summary": reason,
            })
    else:
        if inventory:
            issue = inventory[0]
            stable_issue_id = issue["stable_issue_id"]
            issue_slot_id = issue["issue_slot_id"]
            rule_id = issue["rule_id"]
            locus_id = issue["locus_id"]
            object_id = issue["object_id"]
            finding_code = issue["finding_code"]
        else:
            rule = contract["rules"][0]
            stable_issue_id = None
            issue_slot_id = rule["issue_slot_ids"][0]
            rule_id = rule["rule_id"]
            locus_id = rule["locus_id"]
            object_id = rule["allowed_object_ids"][0]
            finding_code = rule["allowed_finding_codes"][0]
        findings.append({
            "stable_issue_id": stable_issue_id,
            "issue_slot_id": issue_slot_id,
            "rule_id": rule_id,
            "locus_id": locus_id,
            "object_id": object_id,
            "finding_code": finding_code,
            "disposition": "OPEN",
            "evidence_refs": evidence_refs,
            "summary": reason,
        })
    if verdict == "PASS":
        for condition in contract.get("condition_requirements", ()):
            findings.append({
                "stable_issue_id": None,
                "issue_slot_id": condition["issue_slot_id"],
                "rule_id": condition["rule_id"],
                "locus_id": condition["locus_id"],
                "object_id": condition["object_id"],
                "finding_code": "EVIDENCE_INSUFFICIENT",
                "disposition": "RESOLVED",
                "evidence_refs": list(dict.fromkeys([
                    *condition["evidence_refs"], *business_request_refs,
                ])) if condition["kind"] == "SEMANTIC_CONDITION" and business_request_refs
                else condition["evidence_refs"] or evidence_refs,
                "summary": reason,
            })
    return {
        "schema": "SITINA_LOOP_REVIEW_V2",
        "termination_contract_version": contract["termination_contract_version"],
        "acceptance_item_id": contract["acceptance_item_id"],
        "review_subject_lineage": contract["review_subject_lineage"],
        "observed_artifact_ref": contract["observed_artifact_ref"],
        "verdict": verdict,
        "reason": reason,
        "findings": findings,
    }


def scripted_factory(boundary: DevelopmentBoundary, scripts: dict[str, list[list[ProviderToolTurn]]]):
    clients: list[tuple[str, ScriptedMockToolClient]] = []

    class BoundReviewClient(ScriptedMockToolClient):
        def __init__(self, script):
            super().__init__(script)
            self._evidence_requested = False

        def complete_tool_turn(self, *args, messages, **kwargs):
            if not self._evidence_requested:
                self._evidence_requested = True
                return reviewer_evidence_turn(messages, call_prefix="review-proof")
            result = super().complete_tool_turn(*args, messages=messages, **kwargs)
            text = result.text
            try:
                legacy = json.loads(text.replace("__ARTIFACT_REF__", artifact_ref_from_messages(messages)))
            except json.JSONDecodeError:
                return result
            if legacy.get("schema") != "SITINA_LOOP_REVIEW_V1":
                return result
            return ProviderToolTurn(
                json.dumps(review_v2_document(
                    messages,
                    verdict=str(legacy["verdict"]),
                    reason=str(legacy["reason"]),
                )),
                result.tool_calls,
                result.stop_reason,
                result.metadata,
            )

    def factory(role: str, _adapter):
        completion_mode = role == "main" and _adapter.work_purpose == "goal_completion"
        completion_pages = {}
        # Unit responses for the real interpretation phase do not consume a
        # business/reviewer script. A recovered durable decision never invokes
        # this factory for that phase again.
        if _adapter.work_purpose == "goal_interpretation":
            if "goal_interpretation" in scripts:
                client = ScriptedMockToolClient(scripts["goal_interpretation"].pop(0))
            else:
                task = _adapter.backend.get_task(_adapter.task_id)
                document = _adapter.backend.context_memory.read(task.goal_ref)
                goal = str(document["goal"])
                try:
                    structured_goal = json.loads(goal)
                except json.JSONDecodeError:
                    structured_goal = None
                assert not isinstance(structured_goal, (dict, list)), (
                    "structured unit goals need an explicit goal_interpretation script"
                )
                client = ScriptedMockToolClient([turn(json.dumps({"goal_input": {
                    "goal": goal,
                    "constraints": [],
                    "acceptance_conditions": ["Satisfy the existing unit task acceptance contract"],
                    "missing_inputs": [],
                    "question": None,
                }}))])
            clients.append(("goal_interpretation", client))
        elif completion_mode:
            client = BoundReviewClient([turn(json.dumps({
                "schema": "SITINA_LOOP_REVIEW_V1", "verdict": "PASS",
                "reason": "The existing task assertions are satisfied.",
                "artifact_ref": "__ARTIFACT_REF__",
            }))])
            clients.append(("goal_completion", client))
        else:
            client_type = BoundReviewClient if role == "reviewer" else ScriptedMockToolClient
            client = client_type(scripts[role].pop(0))
            clients.append((role, client))
        home = boundary.state_root / "provider-home"
        runtime = AutonomousRuntime(
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
        if completion_mode:
            execute_one = runtime._execute_one
            send = client.complete_tool_turn

            def capture_page(run_id, call):
                result = execute_one(run_id, call)
                if call.name == "sitina_history_query" and result.value.get("status") == "OK":
                    completion_pages[result.value["source_ref"]] = (dict(call.arguments), result.value)
                return result

            def complete_with_native_pages(*args, messages, **kwargs):
                more = [ProviderToolCall(
                    "completion-page-" + str(index) + "-" + str(page["next_offset"]), "sitina_history_query",
                    {**arguments, "offset": page["next_offset"]},
                ) for index, (arguments, page) in enumerate(completion_pages.values()) if page["has_more"]]
                if more:
                    return turn("", *more)
                return send(*args, messages=messages, **kwargs)

            runtime._execute_one = capture_page
            client.complete_tool_turn = complete_with_native_pages
        return runtime

    return factory, clients


def runner_for(boundary: DevelopmentBoundary, scripts: dict[str, list[list[ProviderToolTurn]]]):
    keys = MemoryKeychainBackend()
    factory, clients = scripted_factory(boundary, scripts)
    runner = LoopTaskRunner(
        boundary,
        approve_writes=True,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
    )
    return runner, clients, keys


def test_provider_home_mirrors_nested_configuration_tree(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    nested = boundary.config_root / "mcp"
    nested.mkdir()
    (nested / "servers.yaml").write_text("servers: []\n", encoding="utf-8")
    (nested / "allowlist.yaml").write_text("allow: []\n", encoding="utf-8")

    runner = LoopTaskRunner(boundary, provider_profile="deepseek")
    provider_home = runner._prepare_provider_home()

    servers = provider_home / "config/mcp/servers.yaml"
    allowlist = provider_home / "config/mcp/allowlist.yaml"
    assert servers.read_text(encoding="utf-8") == "servers: []\n"
    assert allowlist.read_text(encoding="utf-8") == "allow: []\n"
    servers_mtime = servers.stat().st_mtime_ns
    stale = provider_home / "config/obsolete.yaml"
    stale.write_text("obsolete: true\n", encoding="utf-8")
    (boundary.config_root / "obsolete.yaml").write_text("obsolete: true\n", encoding="utf-8")
    runner._prepare_provider_home()
    assert servers.stat().st_mtime_ns == servers_mtime
    assert stale.exists()
    (boundary.config_root / "obsolete.yaml").unlink()
    runner._prepare_provider_home()
    assert not stale.exists()
    from sitina.extensions.authority import _configuration_hash

    assert _configuration_hash(provider_home) == _configuration_hash(boundary.source_root)


@pytest.mark.parametrize("target_kind", ["source", "destination"])
def test_provider_home_configuration_mirror_rejects_symlink_entries(
    tmp_path: Path, target_kind: str
) -> None:
    boundary = boundary_fixture(tmp_path)
    outside = tmp_path / "outside.yaml"
    outside.write_text("outside: true\n", encoding="utf-8")
    if target_kind == "source":
        link = boundary.config_root / "mcp-link.yaml"
    else:
        provider_config = boundary.state_root / "provider-home/config"
        provider_config.mkdir(parents=True)
        link = provider_config / "escape.yaml"
    link.symlink_to(outside)

    runner = LoopTaskRunner(boundary, provider_profile="deepseek")
    with pytest.raises(LoopTaskRuntimeError, match="symlink"):
        runner._prepare_provider_home()


def test_code_change_reviewer_feedback_returns_to_rework_cycle(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    scripts = {
        "main": [
            [
                turn("", ProviderToolCall("w1", "sitina_write_file", {"path": "result.txt", "content": "v1"})),
                turn("implemented v1"),
            ],
            [
                turn("", ProviderToolCall("w2", "sitina_edit_file", {"path": "result.txt", "old_string": "v1", "new_string": "v2"})),
                turn("implemented reviewer fix"),
            ],
        ],
        "reviewer": [
            [turn(json.dumps({"schema": "SITINA_LOOP_REVIEW_V1", "verdict": "BLOCK", "reason": "Use v2.", "artifact_ref": "__ARTIFACT_REF__"}))],
            [turn(json.dumps({"schema": "SITINA_LOOP_REVIEW_V1", "verdict": "PASS", "reason": "Verified.", "artifact_ref": "__ARTIFACT_REF__"}))],
        ],
    }
    runner, clients, _keys = runner_for(boundary, scripts)
    result = runner.run(
        task_id="task-code",
        task_kind="code_change",
        goal="Create result.txt",
        check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('result.txt').is_file()"),
    )
    assert result["status"] == "succeeded"
    assert result["review_status"] == "PASS"
    assert result["cycle"] == 2
    assert (boundary.business_workspace / "result.txt").read_text() == "v2"
    second_main = [client for role, client in clients if role == "main"][1]
    assert "Use v2" in second_main.received_messages[0][-1]["content"]


@pytest.mark.parametrize("response", [
    "REVIEW: BLOCK\nDo not output REVIEW: PASS; the change is incorrect.",
    "Example: REVIEW: PASS\nActual: REVIEW: NEEDS_EVIDENCE",
])
def test_review_parser_rejects_pass_substring_counterexamples(response: str) -> None:
    with pytest.raises(ReviewProtocolError, match="one complete JSON object"):
        LoopTaskRunner._review_verdict(
            {"terminal_state": "SUCCEEDED", "response": response},
            acceptance_item_id="outcome-1",
            review_subject_lineage_id="subject",
            artifact_ref="cas:artifact",
            criteria_lineage_id="criteria",
            rules=(),
            queried_source_refs=(),
            unresolved_issues={},
            source_facts={},
            object_fingerprints={},
        )


@pytest.mark.parametrize("task_kind", ["readonly", "no_change"])
def test_readonly_and_no_change_tasks_accept_zero_diff_without_review(
    tmp_path: Path, task_kind: str, monkeypatch
) -> None:
    # Reuse the existing bound-review response fixture for the main-role
    # completion decision. No independent reviewer is invoked by this wrapper.
    original_factory = scripted_factory
    completion_adapters = []
    recorded_checkpoints = {}
    expected_baselines = {}
    main_adapters = []
    interpretation_adapters = []
    actual_main_results = {}
    actual_interpretation_results = {}
    completion_dispatches = []
    completion_tool_hooks = []
    completion_runs = []
    completion_context_owners = []
    evidence_repair_requests = []
    evidence_source_calls = {}
    unbound_read_sources = {}
    completion_history_pages = []
    completion_contexts = []
    completion_prepared_calls = []
    original_steps = LoopTaskRunner._run_attempt_steps

    def capture_steps(runner, backend, task_id, runtime, adapter, prompt, attempt_id):
        try:
            result = original_steps(runner, backend, task_id, runtime, adapter, prompt, attempt_id)
        except Exception as exc:
            if task_id == "remaining-work" and adapter.work_purpose == "goal_completion":
                completion_runs.append((task_id, runtime, attempt_id, {
                    "exception_type": type(exc).__name__, "exception_message": str(exc),
                }))
            raise
        if adapter.work_purpose == "main":
            actual_main_results[task_id] = result
            if task_id.startswith("completion-unbound-"):
                for item in result.get("tool_results", ()):
                    if item["name"] == "sitina_read_file" and item.get("result_source_ref"):
                        from sitina.loop.context_window import LoopContextIndex
                        optional_index = LoopContextIndex(backend.store, task_id)
                        optional_index.refresh()
                        unbound_read_sources[task_id] = next(
                            entry.source_ref for entry in reversed(optional_index.entries)
                            if entry.kind == "operation_intent"
                        )
        elif adapter.work_purpose == "goal_interpretation":
            actual_interpretation_results[task_id] = result
        elif adapter.work_purpose == "goal_completion":
            completion_runs.append((task_id, runtime, attempt_id, dict(result)))
            completion_context_owners.append((task_id, runtime, adapter, runtime.request_assembler))
        return result

    monkeypatch.setattr(LoopTaskRunner, "_run_attempt_steps", capture_steps)
    accepted_task_ids = []
    original_acceptance = LoopBackend.record_acceptance

    def capture_acceptance(backend, task_id, submission, **options):
        assert_effective_goal(submission.details)
        accepted = original_acceptance(backend, task_id, submission, **options)
        accepted_task_ids.append(task_id)
        return accepted

    monkeypatch.setattr(LoopBackend, "record_acceptance", capture_acceptance)

    original_review_verdict = LoopTaskRunner._review_verdict
    optional_citation_checked = []

    def review_with_optional_history(result, **options):
        current_completion_task = completion_adapters[-1].task_id
        optional_source = unbound_read_sources.get(current_completion_task)
        citation_case = (
            options.get("completion_requirements") and optional_source is not None
            and current_completion_task in {"completion-unbound-corrected", "completion-unbound-citation"}
        )
        if citation_case:
            # Exercise the real decision consumer with an authenticated optional
            # history handle, rather than its separately supplied business alias.
            document = json.loads(result["response"])
            document["verdict"] = "NEEDS_EVIDENCE"
            document["reason"] = "A further semantic check is needed."
            assert document["findings"]
            for finding in document["findings"]:
                finding["disposition"] = "OPEN"
                finding["evidence_refs"] = [optional_source]
                finding["summary"] = document["reason"]
            if optional_source not in options["queried_source_refs"]:
                # This real optional handle was only mentioned in the candidate;
                # it must be rejected and named for a native read, never credited.
                from sitina.loop.termination import ReviewProtocolError
                try:
                    original_review_verdict({**result, "response": json.dumps(document)}, **options)
                except ReviewProtocolError as error:
                    assert error.kind == "EVIDENCE_MISSING"
                    assert error.unread_source_refs == (optional_source,)
                    raise
                pytest.fail("unread optional citation was accepted")
            verdict, _ = original_review_verdict(
                {**result, "response": json.dumps(document)}, **options,
            )
            assert verdict == "NEEDS_EVIDENCE"
            optional_citation_checked.append(optional_source)
        return original_review_verdict(result, **options)

    monkeypatch.setattr(LoopTaskRunner, "_review_verdict", staticmethod(review_with_optional_history))

    def completion_factory(test_boundary, responses):
        factory, clients = original_factory(test_boundary, responses)

        def with_completion(role, adapter):
            if adapter.work_purpose != "goal_completion":
                if adapter.work_purpose == "goal_interpretation":
                    interpretation_adapters.append(adapter)
                if adapter.work_purpose == "main":
                    main_adapters.append(adapter)
                    if adapter.task_id == "remaining-work" and sum(
                        item.task_id == adapter.task_id for item in main_adapters
                    ) == 2:
                        # Re-reading the already persisted first observation is
                        # useful context but must not create another completion.
                        first = next(item for item in actual_main_results[adapter.task_id]["tool_results"]
                                     if item["name"] == "sitina_read_file")
                        responses["main"][0].insert(0, turn("", ProviderToolCall(
                            "replay-first-receipt", "sitina_history_query",
                            {"operation": "read", "source_ref": first["result_source_ref"],
                             "offset": 0, "max_bytes": 8192},
                        )))
                return factory(role, adapter)
            assert role == "main"
            assert adapter.mutation_allowed is False
            completion_adapters.append(adapter)
            bound_factory, bound_clients = original_factory(
                test_boundary, {"reviewer": [responses["goal_completion"].pop(0)]},
            )
            runtime = bound_factory("reviewer", adapter)
            execute_one = runtime._execute_one
            run_hook = runtime.hooks.run
            send_completion = runtime.client.complete_tool_turn
            pending_evidence_calls = None
            pagination_calls = set()
            repeated_evidence_read_sent = False
            unbound_reads = 0
            unbound_correction_seen = False

            def checked_completion_send(profile, **arguments):
                nonlocal pending_evidence_calls, repeated_evidence_read_sent, unbound_reads, unbound_correction_seen
                prepared = arguments["prepared_request"]
                assert prepared is completion_prepared_calls[-1].rendered_request
                body = prepared.body_for_send(prepared.identity)
                assert body["response_format"] == {"type": "json_object"}
                assert runtime.goal_completion_only is True
                assert runtime.goal_input_only is False
                assert {tool["function"]["name"] for tool in body["tools"]} == {"sitina_history_query"}
                system = body["messages"][0]["content"]
                assert "When returning a terminal decision without tool calls" in system
                assert "one raw JSON object, with no preface, Markdown fence, or suffix" in system
                assert "goal_input clarification" in system
                evidence_case = adapter.task_id.startswith("completion-evidence-")
                unbound_case = adapter.task_id.startswith("completion-unbound-")
                if evidence_case or unbound_case:
                    payload = json.loads(next(item["content"] for item in body["messages"]
                                              if item["role"] == "user"))
                if evidence_case:
                    feedback = payload.get("runtime_feedback")
                    evidence_repair_requests.append((adapter.task_id, feedback))
                    if feedback and feedback["kind"] == "goal_completion_evidence_repair" and pending_evidence_calls:
                        if adapter.task_id.endswith("corrected"):
                            calls, pending_evidence_calls = pending_evidence_calls, ()
                            return turn("", *calls)
                        if adapter.task_id.endswith("cancel"):
                            pending_evidence_calls = ()
                            adapter.backend.accept_input(
                                adapter.task_id, input_id="cancel-evidence-repair",
                                kind=InputKind.CANCEL, body="Cancel before the missing evidence read.",
                            )
                # Consume the real native byte pages before the scripted final
                # verdict. The evidence-repair case deliberately withholds them
                # until the first incomplete decision has been rejected.
                if not evidence_case or pending_evidence_calls == ():
                    latest = {}
                    for identity, call_arguments, page in completion_history_pages:
                        if identity == adapter.task_id and page.get("status") == "OK":
                            latest[page["source_ref"]] = (call_arguments, page)
                    continuation = []
                    for source_ref, (call_arguments, page) in latest.items():
                        if page["has_more"]:
                            next_arguments = {**call_arguments, "offset": page["next_offset"]}
                            key = (source_ref, page["next_offset"])
                            if key not in pagination_calls:
                                pagination_calls.add(key)
                                continuation.append(ProviderToolCall(
                                    f"next-page-{len(pagination_calls)}", "sitina_history_query", next_arguments,
                                ))
                    if continuation:
                        return turn("", *continuation)
                    if unbound_case:
                        unbound_feedback = payload.get("runtime_feedback")
                        if unbound_feedback and unbound_feedback["kind"] == "goal_completion_evidence_repair":
                            unbound_correction_seen = True
                            if adapter.task_id.endswith("citation") and unbound_reads == 0:
                                source_ref = unbound_read_sources[adapter.task_id]
                                assert source_ref in unbound_feedback["instruction"]
                                unbound_reads += 1
                                return turn("", ProviderToolCall(
                                    "read-rejected-citation", "sitina_history_query",
                                    {"operation": "read", "source_ref": source_ref,
                                     "offset": 0, "max_bytes": 8192},
                                ))
                        required = set(payload["execution_context"]["preflight_source_refs"])
                        completed = {ref for ref, (_, page) in latest.items() if page["has_more"] is False}
                        if (
                            (required <= completed or adapter.task_id.endswith("missing"))
                            and (not unbound_correction_seen or adapter.task_id.endswith("exhausted"))
                            and not adapter.task_id.endswith("citation")
                        ):
                            source_ref = unbound_read_sources[adapter.task_id]
                            assert source_ref not in required
                            unbound_reads += 1
                            return turn("", ProviderToolCall(
                                f"unbound-read-{unbound_reads}", "sitina_history_query",
                                {"operation": "read", "source_ref": source_ref,
                                 "offset": 0, "max_bytes": 8192},
                            ))
                    if (
                        evidence_case and adapter.task_id.endswith("corrected")
                        and not repeated_evidence_read_sent
                    ):
                        repeated_evidence_read_sent = True
                        _, call_arguments, page = next(
                            item for item in reversed(completion_history_pages)
                            if item[0] == adapter.task_id and item[2].get("status") == "OK"
                        )
                        assert page["has_more"] is False
                        return turn("", ProviderToolCall(
                            "repeat-completed-evidence", "sitina_history_query", dict(call_arguments),
                        ))
                response = send_completion(profile, **arguments)
                if evidence_case and pending_evidence_calls is None:
                    expected_sources = set(payload["execution_context"]["preflight_source_refs"])
                    assert {call.arguments["source_ref"] for call in response.tool_calls} == expected_sources
                    assert len(response.tool_calls) == len(expected_sources) > 1
                    evidence_source_calls[adapter.task_id] = response.tool_calls
                    pending_evidence_calls = response.tool_calls[1:]
                    return ProviderToolTurn(
                        response.text, response.tool_calls[:1], response.stop_reason,
                        response.metadata, response.reasoning_content,
                    )
                return response

            monkeypatch.setattr(runtime.client, "complete_tool_turn", checked_completion_send)

            def tracked_dispatch(run_id, call):
                completion_dispatches.append((adapter.task_id, call.name, dict(call.arguments)))
                result = execute_one(run_id, call)
                if call.name == "sitina_history_query":
                    completion_history_pages.append((adapter.task_id, dict(call.arguments), result.value))
                return result

            def tracked_hook(event, payload):
                if event == "before_tool":
                    completion_tool_hooks.append((adapter.task_id, payload["tool"]))
                return run_hook(event, payload)

            monkeypatch.setattr(runtime, "_execute_one", tracked_dispatch)
            monkeypatch.setattr(runtime.hooks, "run", tracked_hook)
            clients.append(("goal_completion", bound_clients[0][1]))
            return runtime

        return with_completion, clients

    monkeypatch.setitem(globals(), "scripted_factory", completion_factory)

    def completion_turn(verdict, reason):
        return turn(json.dumps({
            "schema": "SITINA_LOOP_REVIEW_V1", "verdict": verdict, "reason": reason,
        }))
    boundary = boundary_fixture(tmp_path)
    request = {
        "objective": "Inspect without edits",
        "constraints": ["Read only; preserve every file."],
        "acceptance_criteria": ["Report the actual contents of the selected files."],
        "instructions": "Inspect the selected workspace files.",
    }
    provider_decision = {
        "goal": request["instructions"],
        "constraints": ["Do not write files."],
        "acceptance_conditions": ["Provide an inspection summary."],
        "missing_inputs": [],
        "question": None,
    }
    provider_text = json.dumps({"goal_input": provider_decision})
    scripts = {
        "main": [[turn("analysis complete")]], "reviewer": [],
        "goal_completion": [[completion_turn("PASS", "The requested inspection summary is complete.")]],
    }
    goal = "Inspect without edits"
    if task_kind == "readonly":
        goal = json.dumps(request)
        scripts["goal_interpretation"] = [[turn(provider_text)]]
        clarification = {
            **provider_decision,
            "missing_inputs": ["deployment_environment"],
            "question": "Which deployment environment?",
        }
        assert AutonomousRuntime._goal_input_decision(
            json.dumps({"goal_input": clarification}), required=True, original_request=goal
        ) == {
            **clarification,
            "goal": request["objective"],
            "constraints": request["constraints"],
            "acceptance_conditions": request["acceptance_criteria"],
        }
        for invalid in (
            {**request, "objective": " "},
            {**request, "constraints": "read only"},
            {**request, "acceptance_criteria": []},
        ):
            with pytest.raises(AutonomousRuntimeError, match="structured request"):
                AutonomousRuntime._goal_input_decision(
                    provider_text, required=True, original_request=json.dumps(invalid)
                )
        with pytest.raises(AutonomousRuntimeError, match="goal interpretation lists are invalid"):
            AutonomousRuntime._goal_input_decision(
                json.dumps({"goal_input": {**provider_decision, "constraints": "read only"}}),
                required=True,
                original_request=goal,
            )

        late_clarification = {
            **provider_decision,
            "missing_inputs": ["intended_audience"],
            "question": "What is the intended audience for this release?",
        }
        clarification_json = json.dumps({"goal_input": late_clarification})
        mixed_response = (
            "Both source files have been read. The intended audience is required before the assessment.\n\n"
            + clarification_json
        )
        fenced_response = (
            mixed_response[:-len(clarification_json)]
            + "```json\n" + clarification_json + "\n```"
        )
        expected_clarification = {
            **late_clarification,
            "goal": request["objective"],
            "constraints": request["constraints"],
            "acceptance_conditions": request["acceptance_criteria"],
        }
        for response in (
            clarification_json,
            mixed_response + "\n \t",
            fenced_response,
            fenced_response + "\n \t",
            fenced_response.replace("\n", "\r\n"),
            mixed_response.replace('"goal_input"', r'"goal\u005finput"', 1),
        ):
            assert AutonomousRuntime._goal_input_decision(
                response, required=False, original_request=goal
            ) == expected_clarification
        for response in (
            "analysis complete",
            'The "goal_input" field describes the clarification protocol.',
            'Inspection complete. {"summary": "done"}',
        ):
            assert AutonomousRuntime._goal_input_decision(response, required=False) is None
        for response in (mixed_response, fenced_response):
            with pytest.raises(AutonomousRuntimeError, match="did not return JSON"):
                AutonomousRuntime._goal_input_decision(response, required=True)
        for response in (
            mixed_response + "\nThe assessment is complete.",
            fenced_response.removesuffix("\n```"),
            mixed_response + "\n```",
            fenced_response + "\nThe assessment is complete.",
            fenced_response + "\n" + clarification_json,
            "An unfinished object {\n" + fenced_response,
            fenced_response.replace("```json\n", "```text\n", 1),
            fenced_response.replace("```json\n", "Inline ```json\n", 1),
            fenced_response.replace("\n```", "\n````", 1),
            "```text\nEarlier fenced text\n```\n" + fenced_response,
            fenced_response.replace('"question":', '"question": null, "question":', 1),
            mixed_response + "\n" + clarification_json,
            'Earlier {"summary": "read"}\n' + mixed_response,
            "An unfinished object { " + mixed_response,
            "Prefix " + clarification_json[:-1],
            'Prefix {"goal_input"',
            "Prefix " + json.dumps({"wrapper": {"goal_input": late_clarification}}),
            "Prefix " + json.dumps({"goal_input": {**late_clarification, "constraints": "read only"}}),
            "Prefix " + provider_text,
            'Prefix {"goal_input":' + json.dumps(late_clarification)
            + ',"goal_input":' + json.dumps(late_clarification) + '}',
            "Prefix " + clarification_json.replace('"question":', '"question": null, "question":', 1),
        ):
            with pytest.raises(AutonomousRuntimeError):
                AutonomousRuntime._goal_input_decision(response, required=False, original_request=goal)

    checkpoint_attempt = LoopBackend.checkpoint_attempt
    recorded = []
    recorded_reasons = []
    recorded_source_refs = []
    prepared_goal_phases = []
    prepare_request = LoopRequestAssembler.prepare

    def assert_effective_goal(execution):
        provenance = execution["goal_input_provenance"]
        key, baseline = recorded_checkpoints[provenance["baseline_checkpoint_id"]]
        current_key, current = recorded_checkpoints[provenance["current_checkpoint_id"]]
        assert key == current_key
        assert expected_baselines[key] == baseline["checkpoint_id"]
        assert execution["interpreted_goal_input"] == {
            **current["goal_input"], "acceptance_conditions": baseline["goal_input"]["acceptance_conditions"],
        }
        assert execution["goal_input_source_refs"] == list(dict.fromkeys(
            [*baseline["goal_input_source_refs"], *current["goal_input_source_refs"]]
        ))
        assert provenance["baseline_decision_source_refs"] == baseline["goal_input_source_refs"]
        assert provenance["current_decision_source_refs"] == current["goal_input_source_refs"]

    def checked_prepare(assembler, identity, **arguments):
        prepared = prepare_request(assembler, identity, **arguments)
        current_message = next(
            message for message in prepared.rendered_request.body["messages"]
            if message["role"] == "user"
        )
        execution = json.loads(current_message["content"])["execution_context"]
        if execution.get("phase") == "goal_completion":
            assert arguments["expect_json"] is True
            assert prepared.admission.admitted
            assert prepared.admission.body_hash == prepared.rendered_request.body_hash
            completion_prepared_calls.append(prepared)
            completion_contexts.append((completion_adapters[-1].task_id, execution))
            actual_main = actual_main_results[completion_adapters[-1].task_id]
            assert "provider_response_metadata" not in actual_main
            metadata = actual_main["provider_metadata"]
            assert isinstance(metadata, list) and metadata and isinstance(metadata[-1], dict)
            main_source = metadata[-1]["sitina_history_source_ref"]
            assert execution["main_result_source_ref"] == main_source
            assert main_source in execution["preflight_source_refs"]
            assert_effective_goal(execution)
            assert execution["candidate_response"]
            assert execution["response_contract"]["schema"] == "SITINA_LOOP_REVIEW_V2"
        if execution.get("phase") == "main":
            interpretation_only = execution["goal_input_only"]
            prepared_goal_phases.append(interpretation_only)
            if interpretation_only:
                assert execution["interpreted_goal_input"] is None
                assert execution["goal_input_source_refs"] == []
                assert "required goal_input" in execution["phase_instruction"]
                assert "concise candidate result" not in execution["phase_instruction"]
                assert "concise candidate result" not in arguments["system_prompt"]
            else:
                assert recorded_reasons[-1] == "GOAL_INTERPRETED"
                assert_effective_goal(execution)
        return prepared

    monkeypatch.setattr(LoopRequestAssembler, "prepare", checked_prepare)

    def checked_checkpoint(backend, task_id, **arguments):
        decision = arguments.get("goal_input")
        if decision is not None and task_kind == "readonly":
            for field, replacement in (
                ("goal", "Caller supplied a different objective"),
                ("constraints", ["Caller supplied a different constraint"]),
                ("acceptance_conditions", ["Caller supplied a different acceptance condition"]),
                ("missing_inputs", ["caller_input"]),
                ("question", "Caller supplied a different question?"),
            ):
                with pytest.raises(TaskConflict, match="lacks one current Provider result"):
                    checkpoint_attempt(
                        backend, task_id,
                        **{**arguments, "goal_input": {**decision, field: replacement}},
                    )
        task = checkpoint_attempt(backend, task_id, **arguments)
        if decision is not None:
            checkpoint = next(
                item for item in task.attempt_checkpoints
                if item["checkpoint_id"] == arguments["checkpoint_id"]
            )
            assert checkpoint["original_goal_ref"] == task.goal_ref
            assert checkpoint["original_request_ref"] == task.request_ref
            assert backend.context_memory.read(task.goal_ref)["goal"] == goal
            assert len(checkpoint["goal_input_source_refs"]) == 1
            source = backend.context_memory.read(checkpoint["goal_input_source_refs"][0])
            binding = checkpoint["binding_after_return"]
            baseline_key = (task_id, binding["goal_version"], binding["criteria_lineage_version"])
            expected_baselines.setdefault(baseline_key, checkpoint["checkpoint_id"])
            recorded_checkpoints[checkpoint["checkpoint_id"]] = (baseline_key, dict(checkpoint))
            recorded.append((checkpoint["goal_input"], source["result"]["text"]))
            recorded_reasons.append(checkpoint["reason"])
            recorded_source_refs.append(list(checkpoint["goal_input_source_refs"]))
        return task

    monkeypatch.setattr(LoopBackend, "checkpoint_attempt", checked_checkpoint)
    runner, _clients, _keys = runner_for(boundary, scripts)
    result = runner.run(task_id=f"task-{task_kind}", task_kind=task_kind, goal=goal)
    assert result["status"] == "succeeded"
    assert result["changed_paths"] == []
    assert result["review_status"] == "NOT_REQUIRED"
    assert result["task"]["status"] == "SUCCEEDED"
    actual_main_source = actual_main_results[f"task-{task_kind}"]["provider_metadata"][-1]["sitina_history_source_ref"]
    assert any(
        identity == f"task-{task_kind}" and name == "sitina_history_query"
        and arguments["source_ref"] == actual_main_source
        for identity, name, arguments in completion_dispatches
    )
    assert len(recorded) == 1
    assert recorded_reasons == ["GOAL_INTERPRETED"]
    assert prepared_goal_phases == [True, False]
    decision, raw_provider_text = recorded[0]
    assert decision["goal"] == request["objective"]
    if task_kind == "readonly":
        assert decision == {
            **provider_decision,
            "goal": request["objective"],
            "constraints": request["constraints"],
            "acceptance_conditions": request["acceptance_criteria"],
        }
        assert raw_provider_text == provider_text
        assert json.loads(raw_provider_text)["goal_input"] == provider_decision
    else:
        assert json.loads(raw_provider_text)["goal_input"] == decision

    # The real history group exhausts a one-segment local plan. The next
    # bounded plan must continue that same runtime, consume its authenticated
    # reads and return the decision, without spending a protocol-repair turn.
    for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
        collection.clear()
    scope_scripts = {
        "main": [[turn("Inspection summary ready.")]],
        "goal_completion": [[completion_turn("PASS", "All inspection conditions are satisfied.")]],
        "reviewer": [],
    }
    if task_kind == "readonly":
        scope_scripts["goal_interpretation"] = [[turn(provider_text)]]
    scope_runner, scope_clients, _ = runner_for(
        boundary_fixture(tmp_path / "completion-scope"), scope_scripts,
    )
    scope_runner.attempt_max_control_segments = 1
    scope_result = scope_runner.run(task_id="completion-scope", task_kind=task_kind, goal=goal)
    scope_runs = [item for item in completion_runs if item[0] == "completion-scope"]
    assert scope_result["task"]["status"] == "SUCCEEDED"
    assert scope_runs[-1][3]["attempt_signal"]["reason"] == "COMPLETION_CANDIDATE"
    assert all(item[3]["attempt_signal"]["reason"] == "LOCAL_SCOPE_YIELD" for item in scope_runs[:-1])
    assert len(scope_runs) > 1 and all(item[1] is scope_runs[0][1] for item in scope_runs)
    assert len({item[2] for item in scope_runs}) == len(scope_runs)
    assert sum(role == "goal_completion" for role, _ in scope_clients) == 1
    scope_reads = [
        args["source_ref"] for identity, name, args in completion_dispatches
        if identity == "completion-scope" and name == "sitina_history_query"
    ]
    scope_required = next(context["preflight_source_refs"] for identity, context in completion_contexts
                          if identity == "completion-scope")
    assert len(set(scope_reads)) == len(scope_required)
    scope_offsets = [(args["source_ref"], args["offset"]) for identity, name, args in completion_dispatches
                     if identity == "completion-scope" and name == "sitina_history_query"]
    assert len(scope_offsets) == len(set(scope_offsets))
    assert set(scope_reads) == set(scope_required)
    assert all(context["protocol_repair"] == "" for identity, context in completion_contexts
               if identity == "completion-scope")

    # A real but unbound history read cannot count as progress. With all
    # mandatory evidence retained, one bounded correction can still finish;
    # persistent unbound reads exhaust the existing no-progress limit. Missing
    # mandatory evidence must not gain this recovery route.
    for unbound_case in ("corrected", "exhausted", "missing", "citation"):
        for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
            collection.clear()
        unbound_task = "completion-unbound-" + unbound_case
        unbound_boundary = boundary_fixture(tmp_path / unbound_task)
        unbound_boundary.business_workspace.mkdir(parents=True, exist_ok=True)
        (unbound_boundary.business_workspace / "scope-input.txt").write_text("Inspection fact.\n")
        unbound_scripts = {
            "main": [[
                turn("", ProviderToolCall("read-scope-input", "sitina_read_file", {"path": "scope-input.txt"})),
                turn("Inspection summary ready."),
            ]],
            "goal_completion": [[completion_turn("PASS", "All inspection conditions are satisfied.")
                                 for _ in range(2 if unbound_case == "citation" else 1)]],
            "reviewer": [],
        }
        if task_kind == "readonly":
            unbound_scripts["goal_interpretation"] = [[turn(provider_text)]]
        unbound_runner, unbound_clients, _ = runner_for(unbound_boundary, unbound_scripts)
        unbound_result = unbound_runner.run(task_id=unbound_task, task_kind=task_kind, goal=goal)
        expected_status = {"corrected": "SUCCEEDED", "exhausted": "STALLED", "missing": "WAITING_INPUT",
                           "citation": "SUCCEEDED"}
        assert unbound_result["task"]["status"] == expected_status[unbound_case], unbound_result
        unbound_runs = [row for row in completion_runs if row[0] == unbound_task]
        unknown_runs = [row for row in unbound_runs
                        if row[3]["attempt_signal"]["reason"] == "LOCAL_SCOPE_UNKNOWN_RELEVANCE"]
        assert len(unknown_runs) == {"corrected": 1, "exhausted": 4, "missing": 1, "citation": 0}[unbound_case]
        assert all(row[1] is unbound_runs[0][1] for row in unbound_runs)
        owners = [row for row in completion_context_owners if row[0] == unbound_task]
        current = owners[-1][2].backend.get_task(unbound_task)
        unknown_ids = {row[2] for row in unknown_runs}
        settlements = [entry for entry in current.attempt_settlements if entry["attempt_id"] in unknown_ids]
        assert len(settlements) == len(unknown_runs)
        assert all(entry["count_effect"] == (COUNT_NEUTRAL if unbound_case == "missing" else COUNT_NO_PROGRESS)
                   for entry in settlements)
        assert all(row[3]["attempt_progress"]["relevant_progress"] is False for row in unknown_runs)
        assert not current.active_operations and not current.unresolved_effects
        assert accepted_task_ids.count(unbound_task) == (1 if unbound_case in {"corrected", "citation"} else 0)
        if unbound_case in {"corrected", "citation"}:
            assert optional_citation_checked.count(unbound_read_sources[unbound_task]) == 1
            assert unbound_task not in accepted_task_ids[:-1]
            if unbound_case == "citation":
                optional_source = unbound_read_sources[unbound_task]
                optional_calls = [args for identity, name, args in completion_dispatches
                                  if identity == unbound_task and name == "sitina_history_query"
                                  and args.get("operation") == "read" and args.get("source_ref") == optional_source]
                optional_pages = [(args, page) for identity, args, page in completion_history_pages
                                  if identity == unbound_task and args.get("operation") == "read"
                                  and args.get("source_ref") == optional_source]
                assert optional_calls
                assert [args for args, _ in optional_pages] == optional_calls
                seen_pages = set()
                for ordinal, (args, page) in enumerate(optional_pages):
                    assert page["status"] == "OK" and page["source_ref"] == optional_source
                    page_key = (args["source_ref"], args["offset"])
                    assert page_key not in seen_pages
                    seen_pages.add(page_key)
                    if ordinal == 0:
                        assert args["offset"] == 0
                    if ordinal + 1 < len(optional_pages):
                        assert page["has_more"] is True
                        assert type(page["next_offset"]) is int and page["next_offset"] > args["offset"]
                        assert optional_pages[ordinal + 1][0]["offset"] == page["next_offset"]
                    else:
                        assert page["has_more"] is False
                completion_reasons = [run[3]["attempt_signal"]["reason"] for run in unbound_runs]
                assert completion_reasons
                non_yield_reasons = [reason for reason in completion_reasons if reason != "LOCAL_SCOPE_YIELD"]
                assert non_yield_reasons == ["COMPLETION_CANDIDATE", "COMPLETION_CANDIDATE"], completion_reasons
                assert completion_reasons[-1] == "COMPLETION_CANDIDATE", completion_reasons
        assert sum(role == "goal_completion" for role, _ in unbound_clients) == 1
        required = set(next(context["preflight_source_refs"] for identity, context in completion_contexts
                            if identity == unbound_task))
        required_reads = [(args["source_ref"], args.get("offset", 0))
                          for identity, name, args in completion_dispatches
                          if identity == unbound_task and name == "sitina_history_query"
                          and args.get("source_ref") in required]
        assert len(required_reads) == len(set(required_reads))
        if unbound_case == "missing":
            assert not required_reads
            assert "LOCAL_SCOPE_UNKNOWN_RELEVANCE" in unbound_result["reason"]
        else:
            assert {source for source, _ in required_reads} == required

    # A format correction stays with the runtime that actually read the
    # required sources. It receives feedback and spends the same bounded
    # repair budget, without replaying those reads or accepting invalid JSON.
    for corrected in (True, False):
        for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
            collection.clear()
        repair_task_id = f"completion-format-{corrected}"
        invalid_turn = turn(
            "The assessment is complete.\n```json\n"
            + completion_turn("PASS", "All inspection conditions are satisfied.").text
            + "\n```"
        )
        repair_turns = (
            [invalid_turn, completion_turn("PASS", "All inspection conditions are satisfied.")]
            if corrected else [invalid_turn, invalid_turn, invalid_turn]
        )
        repair_scripts = {
            "main": [[turn("Inspection summary ready.")]],
            "goal_completion": [repair_turns],
            "reviewer": [],
        }
        if task_kind == "readonly":
            repair_scripts["goal_interpretation"] = [[turn(provider_text)]]
        repair_runner, repair_clients, _ = runner_for(
            boundary_fixture(tmp_path / repair_task_id), repair_scripts,
        )
        repair_result = repair_runner.run(task_id=repair_task_id, task_kind=task_kind, goal=goal)
        repair_runs = [item for item in completion_runs if item[0] == repair_task_id]
        assert len(repair_runs) == (2 if corrected else 3)
        assert all(item[1] is repair_runs[0][1] for item in repair_runs)
        assert len({item[2] for item in repair_runs}) == len(repair_runs)
        assert all(item[3]["attempt_signal"]["reason"] == "COMPLETION_CANDIDATE"
                   for item in repair_runs)
        repair_reads = [
            args["source_ref"] for identity, name, args in completion_dispatches
            if identity == repair_task_id and name == "sitina_history_query"
        ]
        repair_required = next(context["preflight_source_refs"] for identity, context in completion_contexts
                               if identity == repair_task_id)
        assert len(set(repair_reads)) == len(repair_required)
        repair_offsets = [(args["source_ref"], args["offset"]) for identity, name, args in completion_dispatches
                          if identity == repair_task_id and name == "sitina_history_query"]
        assert len(repair_offsets) == len(set(repair_offsets))
        assert set(repair_reads) == set(repair_required)
        repair_models = [client for role, client in repair_clients if role == "goal_completion"]
        assert len(repair_models) == 1
        requests = repair_models[0].received_messages
        assert len(requests) == len(repair_runs)
        for messages in requests[1:]:
            request_payload = json.loads(next(item["content"] for item in messages if item["role"] == "user"))
            feedback = request_payload["runtime_feedback"]
            assert feedback["kind"] == "goal_completion_protocol_repair"
            assert "review response is not one complete JSON object" in feedback["instruction"]
            assert "execution_context.response_contract" in feedback["instruction"]
            assert request_payload["execution_context"]["response_contract"]["schema"] == "SITINA_LOOP_REVIEW_V2"
        if corrected:
            assert repair_result["task"]["status"] == "SUCCEEDED"
            assert accepted_task_ids.count(repair_task_id) == 1
        else:
            assert repair_result["task"]["status"] == "STALLED"
            assert "invalid after bounded protocol repair" in repair_result["reason"]
            assert repair_task_id not in accepted_task_ids

    if task_kind == "readonly":
        recorded.clear()
        recorded_reasons.clear()
        recorded_source_refs.clear()
        prepared_goal_phases.clear()
        late_boundary = boundary_fixture(tmp_path / "late-clarification")
        late_scripts = {
            "goal_interpretation": [[turn(provider_text)]],
            "main": [[turn(fenced_response)]],
            "reviewer": [],
        }
        late_runner, _late_clients, _late_keys = runner_for(late_boundary, late_scripts)
        late_result = late_runner.run(
            task_id="task-late-clarification", task_kind=task_kind, goal=goal
        )
        assert late_result["status"] == "waiting_input"
        assert late_result["task"]["status"] == "WAITING_INPUT"
        assert recorded_reasons == ["GOAL_INTERPRETED", "CLARIFICATION_REQUIRED"]
        assert len(recorded) == 2
        assert recorded[-1] == (expected_clarification, fenced_response)
        assert prepared_goal_phases == [True, False]



    # Several accepted, handled user inputs provide real required Journal
    # sources without changing which entry kinds the product must read.
    # Repeat the original goal so all existing acceptance conditions remain.
    original_create_task = LoopBackend.create_task

    def completion_task_with_inputs(backend, **arguments):
        created = original_create_task(backend, **arguments)
        if arguments["task_id"] != "completion-evidence-corrected":
            return created
        for ordinal in range(5):
            backend.accept_input(
                arguments["task_id"], input_id=f"retained-goal-{ordinal}",
                kind=InputKind.MESSAGE, body=arguments["goal"],
            )
            backend.handle_next_input(arguments["task_id"], derive_effects_from_record=True)
        return backend.get_task(arguments["task_id"])

    monkeypatch.setattr(LoopBackend, "create_task", completion_task_with_inputs)
    # Evidence repair retains authenticated pages in the same context. It
    # still obeys the existing repair limit and a newly received cancellation.
    for evidence_case in ("corrected", "exhausted", "cancel"):
        for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
            collection.clear()
        evidence_task = "completion-evidence-" + evidence_case
        evidence_scripts = {
            "main": [[turn("Inspection summary ready." + (" Evidence detail." * 300 if evidence_case == "corrected" else ""))]],
            "goal_completion": [[completion_turn("PASS", "All inspection conditions are satisfied.")
                                 for _ in range(3 if evidence_case == "exhausted" else 2)]],
            "reviewer": [],
        }
        if task_kind == "readonly":
            evidence_scripts["goal_interpretation"] = [[turn(provider_text)]]
        evidence_runner, evidence_clients, _ = runner_for(
            boundary_fixture(tmp_path / evidence_task), evidence_scripts,
        )
        evidence_result = evidence_runner.run(task_id=evidence_task, task_kind=task_kind, goal=goal)
        owners = [row[1:] for row in completion_context_owners if row[0] == evidence_task]
        assert owners and all(all(item is first for item, first in zip(row, owners[0]))
                              for row in owners), evidence_result
        assert sum(role == "goal_completion" for role, _ in evidence_clients) == 1
        initial_calls = evidence_source_calls[evidence_task]
        first_ref = initial_calls[0].arguments["source_ref"]
        missing_refs = [call.arguments["source_ref"] for call in initial_calls[1:]]
        reads = [args["source_ref"] for identity, name, args in completion_dispatches
                 if identity == evidence_task and name == "sitina_history_query"]
        assert list(dict.fromkeys(reads)) == ([first_ref, *missing_refs] if evidence_case == "corrected" else [first_ref])
        feedbacks = [feedback for identity, feedback in evidence_repair_requests
                     if identity == evidence_task and feedback
                     and feedback["kind"] == "goal_completion_evidence_repair"]
        assert feedbacks
        assert all(ref in feedbacks[0]["instruction"] for ref in missing_refs)
        assert all("do not repeat completed reads" in feedback["instruction"] for feedback in feedbacks)
        runs = [row for row in completion_runs if row[0] == evidence_task]
        backend = owners[0][1].backend
        current = backend.get_task(evidence_task)
        assert {row[2] for row in runs} <= {item["attempt_id"] for item in current.attempt_settlements}
        if evidence_case == "corrected":
            instruction = feedbacks[0]["instruction"]
            assert 1024 < len(instruction.encode("utf-8")) <= 4096
            assembler = owners[0][2]
            preserved_feedback = assembler._runtime_feedback
            with pytest.raises(ContextCoreError, match="1024 UTF-8 bytes"):
                assembler.set_runtime_feedback(
                    kind="goal_completion_protocol_repair", instruction=instruction,
                )
            with pytest.raises(ContextCoreError, match="4096 UTF-8 bytes"):
                assembler.set_runtime_feedback(
                    kind="goal_completion_evidence_repair", instruction="é" * 2049,
                )
            assert assembler._runtime_feedback == preserved_feedback
            assert evidence_result["task"]["status"] == "SUCCEEDED"
            assert len(runs) >= 2 and accepted_task_ids.count(evidence_task) == 1
            assert runs[0][3]["attempt_signal"]["reason"] == "COMPLETION_CANDIDATE"
            assert runs[-1][3]["attempt_signal"]["reason"] == "COMPLETION_CANDIDATE"
            assert any(row[3]["attempt_signal"]["reason"] == "CONFIRMED_REPEAT" for row in runs)
            first_page = next(page for identity, args, page in completion_history_pages
                              if identity == evidence_task and page.get("source_ref") == first_ref)
            assert first_page["has_more"] is True
            assert first_ref in feedbacks[0]["instruction"]
            assert f'"{first_ref}":{first_page["next_offset"]}' in feedbacks[0]["instruction"]
            pages = [
                {"name": "sitina_history_query", "status": "ok", "arguments": args, "result": page}
                for identity, args, page in completion_history_pages
                if identity == evidence_task and page.get("source_ref") == first_ref and page.get("status") == "OK"
            ]
            assert len(pages) > 2 and pages[-1]["result"]["has_more"] is False
            binding = first_page["task_session_binding"]
            coverage = {}
            assert not _verified_history_read_source_refs(
                {"tool_results": pages[:1] * 2}, task_session_binding=binding, read_coverage=coverage,
            )
            assert coverage[first_ref]["ranges"] == [(0, first_page["returned_bytes"])]
            assert _verified_history_read_source_refs(
                {"tool_results": pages[1:]}, task_session_binding=binding, read_coverage=coverage,
            ) == {first_ref}
            assert coverage[first_ref]["ranges"] == [(0, first_page["total_bytes"])]
            # A real final page cannot cover an unread prefix/gap.
            assert not _verified_history_read_source_refs(
                {"tool_results": pages[1:]}, task_session_binding=binding, read_coverage={},
            )
            assert not _verified_history_read_source_refs(
                {"tool_results": [pages[0], *pages[2:]]}, task_session_binding=binding, read_coverage={},
            )
            # Do not retain old complete credit after a conflicting identity;
            # a later matching page cannot silently clear that conflict.
            conflicting = {**pages[-1], "result": {**pages[-1]["result"], "content_hash": "0" * 64}}
            assert first_page["content_hash"] != conflicting["result"]["content_hash"]
            assert not _verified_history_read_source_refs(
                {"tool_results": [conflicting, pages[-1]]}, task_session_binding=binding, read_coverage=coverage,
            )
            assert coverage[first_ref]["identity_conflict"] is True
            assert coverage[first_ref]["next_offset"] is None
            assert not _verified_history_read_source_refs(
                {"tool_results": [pages[0], conflicting]}, task_session_binding=binding, read_coverage={},
            )
            # Same native pages, different completion binding: no transferable credit.
            assert not _verified_history_read_source_refs(
                {"tool_results": []}, task_session_binding="other-binding", read_coverage=coverage,
            )
        elif evidence_case == "exhausted":
            assert evidence_result["task"]["status"] == "STALLED"
            assert len(runs) == 3 and "invalid after bounded protocol repair" in evidence_result["reason"]
            assert evidence_task not in accepted_task_ids
        else:
            assert evidence_result["task"]["status"] != "SUCCEEDED"
            assert evidence_task not in accepted_task_ids
            assert evidence_result["task"]["control_intent"] == "CANCEL"

    # A natural-language goal's first source-bound decision remains the
    # baseline through clarification, even when that first decision is a
    # question. Reinterpretation may supply facts but cannot erase obligations.
    saved_goal = goal
    goal = "Inspect every required source, then report the audience without changing any file."
    for first_is_question in (True, False):
        for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
            collection.clear()
        contract_task = "protected-goal-" + str(first_is_question)
        contract_boundary = boundary_fixture(tmp_path / contract_task)
        full_contract = {
            "goal": goal, "constraints": ["Never modify source files."],
            "acceptance_conditions": ["Inspect every required source.", "Report the audience."],
            "missing_inputs": ["audience"] if first_is_question else [],
            "question": "Who is the audience?" if first_is_question else None,
        }
        shrunk = {**full_contract, "acceptance_conditions": ["Report the audience."],
                  "missing_inputs": [], "question": None}
        late_question = {**shrunk, "missing_inputs": ["audience"], "question": "Who is the audience?"}
        contract_scripts = {
            "goal_interpretation": [[turn(json.dumps({"goal_input": full_contract}))],
                                    [turn(json.dumps({"goal_input": shrunk}))]],
            "main": ([] if first_is_question else [[turn(json.dumps({"goal_input": late_question}))]])
                    + [[turn("All required sources inspected; the audience is release coordinators.")]],
            "goal_completion": [[completion_turn("PASS", "Every protected condition has supporting work.")]],
            "reviewer": [],
        }
        contract_runner, _, contract_keys = runner_for(contract_boundary, contract_scripts)
        contract_backend = LoopBackend.open(contract_boundary.state_root, keychain_backend=contract_keys)
        close_backend = contract_backend.close
        contract_runner.backend_factory = lambda _root: contract_backend
        try:
            with monkeypatch.context() as scoped:
                scoped.setattr(contract_backend, "close", lambda: None)
                waiting = contract_runner.run(task_id=contract_task, task_kind=task_kind, goal=goal)
                assert waiting["task"]["status"] == "WAITING_INPUT"
                state = contract_backend.get_task(contract_task)
                original_checkpoints = tuple(dict(item) for item in state.attempt_checkpoints)
                initial_baseline = next(item for item in original_checkpoints if item.get("goal_input"))
                assert initial_baseline["reason"] == ("CLARIFICATION_REQUIRED" if first_is_question else "GOAL_INTERPRETED")
                with LoopAuthorityLease(contract_boundary.state_root):
                    contract_backend.accept_input(contract_task, input_id="audience-answer",
                        kind=InputKind.CLARIFICATION, body=json.dumps({
                            "task_id": contract_task, "question_id": state.waiting_reason["blocker_id"],
                            "goal_version": state.goal_version, "acceptance_version": state.acceptance_version,
                            "question_input_seq": state.handled_input_seq, "answer": "Release coordinators.",
                        }))
                    contract_backend.handle_next_input(contract_task, derive_effects_from_record=True)
                    finished = contract_runner.run_existing(contract_backend, task_id=contract_task, task_kind=task_kind)
                assert finished["task"]["status"] == "SUCCEEDED"
                current = contract_backend.get_task(contract_task)
                assert current.goal_version == state.goal_version
                assert current.handled_input_seq == state.handled_input_seq + 1
                assert tuple(dict(item) for item in current.attempt_checkpoints[:len(original_checkpoints)]) == original_checkpoints
                contexts = [context for identity, context in completion_contexts if identity == contract_task]
                assert contexts and contexts[-1]["interpreted_goal_input"]["acceptance_conditions"] == full_contract["acceptance_conditions"]
                assert contexts[-1]["interpreted_goal_input"]["constraints"] == full_contract["constraints"]
                assert contexts[-1]["goal_input_provenance"]["baseline_checkpoint_id"] == initial_baseline["checkpoint_id"]
                assert contexts[-1]["goal_input_provenance"]["current_checkpoint_id"] != initial_baseline["checkpoint_id"]
                assert recorded[-1][0]["acceptance_conditions"] == shrunk["acceptance_conditions"]
                assert recorded[-1][1] == json.dumps({"goal_input": shrunk})
        finally:
            close_backend()
    goal = saved_goal
    # Prose that explicitly waits for confirmation must not become SUCCEEDED.
    for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
        collection.clear()
    prose_boundary = boundary_fixture(tmp_path / "prose-confirmation")
    confirmation = {
        **decision, "missing_inputs": ["midpoint_confirmation"],
        "question": "May I continue with the remaining source files?",
    }
    prose_scripts = {
        "main": [[turn("I inspected the first portion. I will not continue until you confirm.")]],
        "goal_completion": [[turn(json.dumps({"goal_input": confirmation}))]],
        "reviewer": [],
    }
    if task_kind == "readonly":
        prose_scripts["goal_interpretation"] = [[turn(provider_text)]]
    prose_runner, prose_clients, _ = runner_for(prose_boundary, prose_scripts)
    prose_result = prose_runner.run(task_id="prose-confirmation", task_kind=task_kind, goal=goal)
    assert prose_result["task"]["status"] == "WAITING_INPUT"
    assert recorded_reasons == ["GOAL_INTERPRETED", "CLARIFICATION_REQUIRED"]
    assert recorded[-1][0]["question"] == confirmation["question"]
    assert "prose-confirmation" not in accepted_task_ids
    assert [role for role, _ in prose_clients] == ["goal_interpretation", "main", "goal_completion"]

    # A malformed completion clarification uses the same bounded protocol
    # repair as other completion decisions, without admitting its goal_input.
    original_goal = goal
    required_obligations = [
        *request["acceptance_criteria"],
        "Obtain gate confirmation before continuing the remaining sources.",
        "Obtain the intended audience before the final assessment.",
    ]
    goal = json.dumps({**request, "acceptance_criteria": required_obligations})
    invalid_completion = {
        **decision, "goal": request["objective"], "constraints": request["constraints"],
        "acceptance_conditions": required_obligations,
        "missing_inputs": ["gate_confirmation_and_continuation_authorization", "intended_audience"],
        "question": "May I continue, and who is the intended audience?",
    }
    invalid_completion_text = "The review found two outstanding obligations.\n```json\n" + json.dumps(
        {"goal_input": invalid_completion},
    ) + "\n```"
    corrected_completion = {
        **invalid_completion,
        "missing_inputs": ["gate_confirmation_and_continuation_authorization"],
        "question": "May I continue with the remaining source files?",
    }
    corrected_completion_text = json.dumps({"goal_input": corrected_completion})
    with pytest.raises(GoalInputProtocolError, match="at most one missing input"):
        AutonomousRuntime._goal_input_decision(
            invalid_completion_text, required=False, original_request=goal,
        )
    for repaired in (True, False):
        for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
            collection.clear()
        protocol_task = "goal-input-repaired" if repaired else "goal-input-exhausted"
        protocol_scripts = {
            "goal_interpretation": [[turn(provider_text)]],
            "main": [[turn("The first portion is ready; confirmation and audience remain outstanding.")]],
            "goal_completion": (
                [[turn(invalid_completion_text)], [turn(corrected_completion_text)]]
                if repaired else [[turn(invalid_completion_text)] for _ in range(3)]
            ),
            "reviewer": [],
        }
        protocol_runner, protocol_clients, _ = runner_for(
            boundary_fixture(tmp_path / protocol_task), protocol_scripts,
        )
        protocol_result = protocol_runner.run(task_id=protocol_task, task_kind=task_kind, goal=goal)
        assert protocol_result["task"]["status"] == ("WAITING_INPUT" if repaired else "STALLED")
        assert protocol_task not in accepted_task_ids
        assert sum(role == "goal_completion" for role, _ in protocol_clients) == (2 if repaired else 3)
        assert recorded_reasons == (["GOAL_INTERPRETED", "CLARIFICATION_REQUIRED"] if repaired
                                    else ["GOAL_INTERPRETED"])
        assert all(raw != invalid_completion_text for _, raw in recorded)
        assert all(value["goal"] == request["objective"] for value, _ in recorded)
        assert all(value["constraints"] == request["constraints"] for value, _ in recorded)
        assert all(value["acceptance_conditions"] == required_obligations for value, _ in recorded)
        protocol_adapters = [adapter for adapter in completion_adapters if adapter.task_id == protocol_task]
        protocol_backend = protocol_adapters[-1].backend
        current = protocol_backend.get_task(protocol_task)
        assert protocol_backend.context_memory.read(current.goal_ref)["goal"] == goal
        attempt_ids = {adapter.business_attempt_id for adapter in protocol_adapters}
        assert attempt_ids <= {item["attempt_id"] for item in current.attempt_settlements}
        contexts = [context for identity, context in completion_contexts if identity == protocol_task]
        assert contexts[0]["protocol_repair"] == ""
        repair_start = next(index for index, context in enumerate(contexts) if context["protocol_repair"])
        assert all(context["protocol_repair"] == "" for context in contexts[:repair_start])
        assert all("Invalid goal_input protocol" in context["protocol_repair"] for context in contexts[repair_start:])
        repaired_context = next(context for context in contexts if context["protocol_repair"])
        assert "not a valid goal checkpoint" in repaired_context["protocol_repair"]
        assert "every outstanding obligation" in repaired_context["protocol_repair"]
        new_sources = set(repaired_context["preflight_source_refs"]) - set(contexts[0]["preflight_source_refs"])
        assert len(new_sources) == 1
        assert any(identity == protocol_task and args["source_ref"] in new_sources
                   for identity, name, args in completion_dispatches if name == "sitina_history_query")
        invalid_results = [
            protocol_backend.context_memory.read(operation.result_ref)
            for operation in current.operations.values() if operation.result_ref
        ]
        assert any(isinstance(item.get("result"), dict) and item["result"].get("text") == invalid_completion_text
                   for item in invalid_results)
        if repaired:
            assert recorded[-1] == (corrected_completion, corrected_completion_text)
        else:
            assert "invalid after bounded protocol repair" in protocol_result["reason"]
    goal = original_goal

    # A malformed optional clarification in the main phase preserves the
    # completed read and request context. It is not a goal decision or progress;
    # bounded correction must settle normally, including unsafe/no-budget paths.
    for scenario in ("corrected", "exhausted", "tool-chain", "unbound", "segment-budget", "cancel",
                     "required-corrected", "required-exhausted", "required-tool-chain",
                     "required-unbound", "required-segment-budget", "required-cancel"):
        required_input = scenario.startswith("required-")
        case = scenario.removeprefix("required-")
        for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
            collection.clear()
        main_task = "main-input-" + scenario
        main_boundary = boundary_fixture(tmp_path / main_task)
        main_boundary.business_workspace.mkdir(parents=True, exist_ok=True)
        selected = main_boundary.business_workspace / "selected.txt"
        selected.write_text("Read this once; do not replay it.", encoding="utf-8")
        main_decision = {
            **decision, "missing_inputs": ["next_source"],
            "question": "Which source should I inspect next?",
        }
        valid_text = json.dumps({"goal_input": main_decision})
        invalid_text = (json.dumps({"result": "Already finished."}) if required_input
                        else valid_text + "\nThe task is complete.")
        rejected_calls = (
            ProviderToolCall("rejected-read", "sitina_read_file", {"path": "selected.txt"}),
        ) if case == "tool-chain" else ()
        bad = turn(invalid_text, *rejected_calls)
        use_read = not required_input and case != "segment-budget"
        sequence = ([turn("", ProviderToolCall(
            "read-once", "sitina_read_file", {"path": "selected.txt"},
        ))] if use_read else []) + (
            [bad, turn(valid_text)] if case == "corrected"
            else [bad, bad, bad] if case == "exhausted"
            else [bad]
        )
        main_scripts = {"main": [sequence], "reviewer": []}
        if required_input:
            main_scripts = {"goal_interpretation": [sequence], "main": [], "reviewer": []}
        elif task_kind == "readonly":
            main_scripts["goal_interpretation"] = [[turn(provider_text)]]
        main_runner, main_clients, _ = runner_for(main_boundary, main_scripts)
        if case == "segment-budget":
            main_runner.attempt_max_control_segments = 1
        original_provider_call = LoopOperationAdapter.provider_call
        original_decision = AutonomousRuntime._goal_input_decision

        def supplied_source(adapter, run_id, turn_index, dispatch):
            value = original_provider_call(adapter, run_id, turn_index, dispatch)
            if adapter.work_purpose == ("goal_interpretation" if required_input else "main") and value.text == invalid_text:
                return ProviderToolTurn(
                    value.text, value.tool_calls, value.stop_reason,
                    {**value.metadata, "sitina_history_source_ref": "history:unbound-current-response"},
                    value.reasoning_content,
                )
            return value

        def cancelled_decision(text, **arguments):
            try:
                return original_decision(text, **arguments)
            except GoalInputProtocolError:
                adapters = interpretation_adapters if required_input else main_adapters
                adapter = next(item for item in adapters if item.task_id == main_task)
                adapter.backend.accept_input(
                    main_task, input_id="cancel-main-protocol", kind=InputKind.CANCEL,
                    body="Cancel instead of repairing this response.",
                )
                raise

        with monkeypatch.context() as scoped:
            if case == "unbound":
                scoped.setattr(LoopOperationAdapter, "provider_call", supplied_source)
            elif case == "cancel":
                scoped.setattr(AutonomousRuntime, "_goal_input_decision", staticmethod(cancelled_decision))
            main_result = main_runner.run(task_id=main_task, task_kind=task_kind, goal=goal)
        models = [client for role, client in main_clients
                  if role == ("goal_interpretation" if required_input else "main")]
        assert len(models) == 1
        assert len(models[0].received_messages) == len(sequence)
        assert main_task not in accepted_task_ids
        adapters = interpretation_adapters if required_input else main_adapters
        adapter = next(item for item in adapters if item.task_id == main_task)
        current = adapter.backend.get_task(main_task)
        phase_results = actual_interpretation_results if required_input else actual_main_results
        saved_main = phase_results[main_task]
        assert saved_main["provider_call_count"] == len(sequence)
        assert len(saved_main["request_admission_receipts"]) == len(sequence)
        assert selected.read_text(encoding="utf-8") == "Read this once; do not replay it."
        dispatched_tools = [
            item for item in current.operations.values() if item.operation_id.startswith("tool-")
        ]
        assert len(dispatched_tools) == (1 if use_read else 0)
        rejected_checkpoints = [
            item for item in current.attempt_checkpoints
            if item["reason"] == "GOAL_INPUT_PROTOCOL_REJECTED"
        ]
        assert len(rejected_checkpoints) == (3 if case == "exhausted" else 1)
        assert all("goal_input" not in item and item["action_observations"] == []
                   and item["operation_refs"] for item in rejected_checkpoints)
        assert rejected_checkpoints[-1]["scope_consumed"]["provider_responses"] == (
            len(sequence) - 1 if case == "corrected" else len(sequence)
        )
        assert all(value != invalid_text for _, value in recorded)
        assert saved_main["attempt_id"] in {item["attempt_id"] for item in current.attempt_settlements}
        if case in {"corrected", "exhausted"}:
            for messages in models[0].received_messages[1 if required_input else 2:]:
                content = json.loads(next(item["content"] for item in messages if item["role"] == "user"))
                repair = content["runtime_feedback"]
                assert repair["kind"] == "main_goal_input_protocol_repair"
                assert "not a valid goal checkpoint" in repair["instruction"]
                assert "Do not replay completed tools" in repair["instruction"]
                assert "ALL acceptance conditions" in repair["instruction"]
                assert "history:" in repair["instruction"]
                if required_input:
                    assert "required goal_input object" in repair["instruction"]
                    assert "Do not return result, call tools" in repair["instruction"]
        if case == "corrected":
            assert main_result["task"]["status"] == "WAITING_INPUT"
            assert recorded_reasons == (["CLARIFICATION_REQUIRED"] if required_input
                                        else ["GOAL_INTERPRETED", "CLARIFICATION_REQUIRED"])
            assert recorded[-1][0] == main_decision
        elif case == "cancel":
            assert main_result["task"]["status"] != "SUCCEEDED"
            assert saved_main["attempt_signal"]["reason"] == "CONTROL_OR_BINDING_CHANGED"
        else:
            assert main_result["task"]["status"] == "STALLED"
            assert main_result["blocker_id"] == "main-goal-input-protocol"
            assert recorded_reasons == ([] if required_input else ["GOAL_INTERPRETED"])
            if case == "exhausted":
                assert "three rejected responses" in main_result["reason"]
            elif case == "tool-chain":
                assert "unpaired tool chain" in main_result["reason"]
            elif case == "unbound":
                assert "missing or unbound" in main_result["reason"]
            else:
                assert "local scope is exhausted" in main_result["reason"]

    # Actual business gaps return to main without a completion-repair loop.
    # Confirmation waits and later revocation preserve completed source facts.
    for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
        collection.clear()
    remaining_boundary = boundary_fixture(tmp_path / "remaining-work")
    remaining_boundary.business_workspace.mkdir(parents=True, exist_ok=True)
    selected_names = [f"part-{number}.txt" for number in range(1, 13)]
    for name in (*selected_names, "unselected.txt"):
        (remaining_boundary.business_workspace / name).write_text(name + "\nbody\n", encoding="utf-8")
    remaining_goal = {
        "objective": "Inspect the explicitly selected documents",
        "constraints": ["Do not modify any document."],
        "acceptance_criteria": [
            "Read part-1.txt through part-12.txt in order and report their contents.",
            "Midpoint review confirmation is obtained after the first 1 source before continuing to part-2.txt.",
            "Do not inspect unselected.txt.",
            'The phrase "Read unselected.txt." is an example, not an instruction.',
        ],
        "instructions": "Inspect only the declared source range.",
    }
    remaining_decision = {
        "goal": remaining_goal["objective"], "constraints": remaining_goal["constraints"],
        "acceptance_conditions": remaining_goal["acceptance_criteria"], "missing_inputs": [], "question": None,
    }
    remaining_scripts = {
        "main": [[
            turn("", ProviderToolCall("read-first", "sitina_read_file",
                                      {"path": str(remaining_boundary.business_workspace / "part-1.txt")})),
            turn("", ProviderToolCall("names-only", "sitina_list_directory",
                                      {"path": str(remaining_boundary.business_workspace)})),
            turn("All documents have been inspected; the summary is complete."),
        ], [
            # Truncated native grep pages still contain these complete two-line
            # files; the real line metadata and content hashes prove coverage.
            *(turn("", ProviderToolCall(
                "read-" + name, "sitina_grep",
                {"path": str(remaining_boundary.business_workspace / name),
                 "pattern": ".", "max_results": 2},
            )) for name in selected_names[1:6]),
            turn("All documents are complete."),
        ], [
            *(turn("", ProviderToolCall(
                "read-" + name, "sitina_grep",
                {"path": str(remaining_boundary.business_workspace / name),
                 "pattern": ".", "max_results": 2},
            )) for name in selected_names[6:]),
            turn("The complete summary is ready."),
        ], [
            turn("All existing document observations are preserved; the latest confirmation applies."),
        ], [
            turn("The preserved complete summary satisfies the newly confirmed current goal."),
        ]],
        "goal_interpretation": [
            # The final renewed-confirmation requires its own current-binding interpretation.
            [turn(json.dumps({"goal_input": remaining_decision}))] for _ in range(5)
        ],
        "goal_completion": [
            [completion_turn("PASS", "All work is complete.")],
            [completion_turn("PASS", "All work is complete.")],
            [completion_turn("PASS", "Every declared source is complete."),
             completion_turn("PASS", "Every condition now has its cited evidence.")],
            [completion_turn("PASS", "An earlier approval authorized continuation.")],
            [completion_turn("PASS", "Every current condition has actual evidence.")],
        ],
        "reviewer": [],
    }
    condition_document = review_v2_document
    decision_dispatch_counts = []

    def remaining_document(messages, **arguments):
        document = condition_document(messages, **arguments)
        decision_dispatch_counts.append(sum(identity == "remaining-work" for identity, _, _ in completion_dispatches))
        ordinal = len(decision_dispatch_counts)
        if ordinal == 1 and task_kind == "readonly" or ordinal == 3:
            document["findings"] = []
        if ordinal == 4:
            assert "remaining-work" not in accepted_task_ids
            completion_adapters[-1].backend.accept_input(
                "remaining-work", input_id="later-revocation", kind=InputKind.CORRECTION,
                body="Midpoint review is revoked; preserve the completed work.",
            )
        return document

    from sitina.loop.task_runtime import _completion_confirmation_disposition
    prior_goal = goal
    goal = json.dumps(remaining_goal)
    assert _completion_confirmation_disposition(
        remaining_goal["acceptance_criteria"][1], "The midpoint review is approved; continue."
    ) == "APPROVED"
    assert _completion_confirmation_disposition(
        remaining_goal["acceptance_criteria"][1], '"Midpoint review is approved"; this is quoted.'
    ) is None
    assert _completion_confirmation_disposition(
        remaining_goal["acceptance_criteria"][1],
        "Midpoint review is approved; Midpoint review is not approved.",
    ) == "REJECTED"
    with monkeypatch.context() as scoped:
        scoped.setitem(globals(), "review_v2_document", remaining_document)
        remaining_runner, remaining_clients, remaining_keys = runner_for(remaining_boundary, remaining_scripts)
        remaining_backend = LoopBackend.open(remaining_boundary.state_root, keychain_backend=remaining_keys)
        remaining_close = remaining_backend.close
        scoped.setattr(remaining_backend, "close", lambda: None)
        remaining_runner.backend_factory = lambda _root: remaining_backend
        try:
            first_wait = remaining_runner.run(task_id="remaining-work", task_kind=task_kind, goal=goal)
            assert first_wait["task"]["status"] == "WAITING_INPUT"
            assert len(decision_dispatch_counts) == 1
            assert "remaining-work" not in accepted_task_ids
            with LoopAuthorityLease(remaining_boundary.state_root):
                remaining_backend.accept_input(
                    "remaining-work", input_id="midpoint-confirmation", kind=InputKind.CORRECTION,
                    body="Midpoint review is approved; continue with the next unprocessed source. Preserve completed work.",
                )
                remaining_backend.handle_next_input("remaining-work", derive_effects_from_record=True)
                revoked_wait = remaining_runner.run_existing(
                    remaining_backend, task_id="remaining-work", task_kind=task_kind,
                )
            assert revoked_wait["task"]["status"] == "WAITING_INPUT"
            assert len(decision_dispatch_counts) == 5
            assert "remaining-work" not in accepted_task_ids
            revoked_view = [context["business_evidence"] for identity, context in completion_contexts
                            if identity == "remaining-work"][-1]
            revoked = revoked_view["condition_observations"][1]["confirmation"]
            assert revoked["historical_confirmation_satisfied"] is True
            assert revoked["historical_approval_ref"]
            assert revoked["current_disposition"] == "REJECTED"
            assert revoked["requires_user_input"] is True
            assert revoked["current_input_ref"] != revoked["historical_approval_ref"]
            assert [item["path"] for item in revoked_view["completed_sources"]] == sorted(selected_names)
            with LoopAuthorityLease(remaining_boundary.state_root):
                remaining_backend.accept_input(
                    "remaining-work", input_id="renewed-confirmation", kind=InputKind.CORRECTION,
                    body="Midpoint review is confirmed; use the already completed work.",
                )
                remaining_backend.handle_next_input("remaining-work", derive_effects_from_record=True)
                remaining_result = remaining_runner.run_existing(
                    remaining_backend, task_id="remaining-work", task_kind=task_kind,
                )
        except IndexError as exc:
            sent_clients = [client for role, client in remaining_clients
                            if role == "goal_completion" and client.received_messages]
            last_payload = json.loads(next(message["content"] for message in sent_clients[-1].received_messages[-1]
                                           if message["role"] == "user")) if sent_clients else {}
            last_views = [context["business_evidence"] for identity, context in completion_contexts
                          if identity == "remaining-work"]
            run_details = [{key: result[key] for key in (
                "exception_type", "exception_message", "status", "attempt_signal", "response", "reason",
            ) if key in result} for identity, _, _, result in completion_runs if identity == "remaining-work"]
            raise AssertionError(json.dumps({
                "runtime_feedback": last_payload.get("runtime_feedback"),
                "business_evidence": last_views[-1] if last_views else None,
                "completion_run_details": run_details,
                "completion_provider_calls": sum(len(client.received_messages) for client in sent_clients),
            })) from exc
        finally:
            remaining_close()
    assert remaining_result["task"]["status"] == "SUCCEEDED"
    assert remaining_result["review_status"] == "NOT_REQUIRED"
    main_clients = [client for role, client in remaining_clients if role == "main"]
    assert len(main_clients) == 5
    assert sum(role == "goal_completion" for role, _ in remaining_clients) == 5
    assert len(decision_dispatch_counts) == 6
    # A pure missing-positive-finding repair reuses all authenticated pages.
    assert decision_dispatch_counts[2] == decision_dispatch_counts[3]
    assert "committed_business_state" in json.dumps(main_clients[2].received_messages[0])
    second_context = json.loads(next(
        message["content"] for message in main_clients[1].received_messages[0]
        if message["role"] == "user"
    ))["execution_context"]
    assert second_context["goal_input_provenance"]["baseline_checkpoint_id"]
    views = [context["business_evidence"] for identity, context in completion_contexts
             if identity == "remaining-work"]
    assert views[0]["condition_observations"][0]["missing_paths"] == selected_names[1:]
    assert any(view["condition_observations"][0]["missing_paths"] == selected_names[6:] for view in views)
    final = views[-1]
    assert final["binding"]["input_seq"] > views[0]["binding"]["input_seq"]
    assert final["condition_observations"][1]["host_observation_satisfied"] is True
    assert final["condition_observations"][1]["confirmation"]["current_disposition"] == "APPROVED"
    assert views[0]["condition_observations"][1]["host_observation_satisfied"] is False
    assert final["condition_observations"][0]["condition_id"] != views[0]["condition_observations"][0]["condition_id"]
    assert accepted_task_ids.count("remaining-work") == 1
    assert final["condition_observations"][0]["host_observation_satisfied"] is True
    assert final["condition_observations"][0]["required_paths"] == selected_names
    assert [item["path"] for item in final["completed_sources"]] == sorted(selected_names)
    assert next(item for item in final["completed_sources"] if item["path"] == "part-1.txt") == views[0]["completed_sources"][0]
    assert all(item["kind"] == "SEMANTIC_CONDITION" and item["required_paths"] == []
               and item["host_observation_satisfied"] is None for item in final["condition_observations"][2:])
    assert sum(item["tool"] == "sitina_read_file" for item in final["business_facts"]) == 1
    assert sum(item["tool"] == "sitina_grep" for item in final["business_facts"]) == 11
    history_facts = [item for item in final["business_facts"] if item["tool"] == "sitina_history_query"]
    assert history_facts
    assert all(item["observation_kind"] == "COMMITTED_HISTORY_QUERY_RESULT"
               and item["content_objects"] == [] and item["returned_line_ranges"] == {}
               for item in history_facts)
    assert all(item["source_ref"] not in final["condition_observations"][0]["evidence_refs"]
               for item in history_facts)
    directory_facts = [item for item in final["business_facts"] if item["tool"] == "sitina_list_directory"]
    assert directory_facts
    assert all(item["content_objects"] == [] and item["returned_line_ranges"] == {} for item in directory_facts)
    assert all(item["source_ref"] not in final["condition_observations"][0]["evidence_refs"] for item in directory_facts)
    for identity, context in completion_contexts:
        if identity != "remaining-work":
            continue
        for requirement in context["response_contract"]["condition_requirements"]:
            if requirement["kind"] != "SEMANTIC_CONDITION":
                continue
            for fact in context["business_evidence"]["business_facts"]:
                assert fact["source_ref"] in requirement["allowed_evidence_refs"]
                if fact.get("request_source_ref"):
                    assert fact["request_source_ref"] in requirement["allowed_evidence_refs"]
    assert all(item["truncated"] is True for item in final["business_facts"] if item["tool"] == "sitina_grep")
    assert recorded_reasons == ["GOAL_INTERPRETED"] * 5
    assert all(item[0]["goal"] == remaining_goal["objective"] for item in recorded)
    assert not any(role == "reviewer" for role, _ in remaining_clients)
    goal = prior_goal

    # A decision bound to another artifact never reaches acceptance, even
    # after all three existing bounded protocol-repair attempts.
    for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
        collection.clear()
    original_document = review_v2_document
    stale_decision_count = 0

    def stale_document(messages, **arguments):
        nonlocal stale_decision_count
        stale_decision_count += 1
        document = original_document(messages, **arguments)
        document["observed_artifact_ref"] = "cas:" + "0" * 64
        return document

    with monkeypatch.context() as scoped:
        scoped.setitem(globals(), "review_v2_document", stale_document)
        stale_scripts = {
            "main": [[turn("Inspection summary ready.")]],
            "goal_completion": [[completion_turn("PASS", "Done.") for _ in range(3)]],
            "reviewer": [],
        }
        if task_kind == "readonly":
            stale_scripts["goal_interpretation"] = [[turn(provider_text)]]
        stale_runner, stale_clients, _ = runner_for(
            boundary_fixture(tmp_path / "stale-completion"), stale_scripts,
        )
        stale_result = stale_runner.run(task_id="stale-completion", task_kind=task_kind, goal=goal)
    assert stale_result["task"]["status"] == "STALLED"
    assert "stale-completion" not in accepted_task_ids
    assert stale_decision_count == 3
    assert sum(role == "goal_completion" for role, _ in stale_clients) == 1

    # An input arriving while a PASS decision is being returned invalidates it.
    for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
        collection.clear()
    injected = False

    def canceled_document(messages, **arguments):
        nonlocal injected
        document = original_document(messages, **arguments)
        if not injected:
            injected = True
            adapter = completion_adapters[-1]
            adapter.backend.accept_input(
                adapter.task_id, input_id="cancel-during-goal-completion",
                kind=InputKind.CANCEL, body="Cancel before accepting this completion.",
            )
        return document

    with monkeypatch.context() as scoped:
        scoped.setitem(globals(), "review_v2_document", canceled_document)
        canceled_scripts = {
            "main": [[turn("Inspection summary ready.")]],
            "goal_completion": [[completion_turn("PASS", "All conditions are satisfied.")]],
            "reviewer": [],
        }
        if task_kind == "readonly":
            canceled_scripts["goal_interpretation"] = [[turn(provider_text)]]
        canceled_runner, _, _ = runner_for(
            boundary_fixture(tmp_path / "input-drift"), canceled_scripts,
        )
        canceled_runner.attempt_max_control_segments = 1
        canceled_result = canceled_runner.run(task_id="input-drift", task_kind=task_kind, goal=goal)
    assert injected
    assert canceled_result["task"]["status"] != "SUCCEEDED"
    assert "input-drift" not in accepted_task_ids

    # A too-small required read and a missing source remain separate errors.
    # Actual native minimum/page limits must drive the executable feedback;
    # neither failed request can satisfy the real main-source requirement.
    original_evidence_turn = reviewer_evidence_turn

    def evidence_without_main(messages, **options):
        full = original_evidence_turn(messages, **options)
        execution = json.loads(messages[0]["content"])["execution_context"]
        main_source = execution["main_result_source_ref"]
        calls = tuple(call for call in full.tool_calls if call.arguments["source_ref"] != main_source)
        assert len(calls) == len(full.tool_calls) - 1
        missing_source = main_source[:-1] + ("0" if main_source[-1] != "0" else "1")
        calls += (
            ProviderToolCall("small-main", "sitina_history_query", {
                "operation": "read", "source_ref": main_source, "offset": 0, "max_bytes": 768,
            }),
            ProviderToolCall("missing-source", "sitina_history_query", {
                "operation": "read", "source_ref": missing_source, "offset": 0, "max_bytes": 4096,
            }),
        )
        return ProviderToolTurn(full.text, calls, "tool_calls", full.metadata)

    for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
        collection.clear()
    with monkeypatch.context() as scoped:
        scoped.setitem(globals(), "reviewer_evidence_turn", evidence_without_main)
        missing_source_scripts = {
            "main": [[turn("Inspection summary ready.")]],
            "goal_completion": [[completion_turn("PASS", "Done.") for _ in range(3)]],
            "reviewer": [],
        }
        if task_kind == "readonly":
            missing_source_scripts["goal_interpretation"] = [[turn(provider_text)]]
        missing_runner, _, _ = runner_for(
            boundary_fixture(tmp_path / "missing-main-source"), missing_source_scripts,
        )
        missing_result = missing_runner.run(
            task_id="missing-main-source", task_kind=task_kind, goal=goal,
        )
    assert missing_result["task"]["status"] == "STALLED"
    assert "every required history source" in missing_result["reason"]
    assert "missing-main-source" not in accepted_task_ids
    final_read_feedback = json.loads(missing_result["reason"].split("every required history source: ", 1)[1])
    main_source = actual_main_results["missing-main-source"]["provider_metadata"][-1]["sitina_history_source_ref"]
    assert final_read_feedback["missing_source_refs"] == [main_source]
    # The same runtime keeps its successful reads. The original failed-page
    # feedback remains in its first durable settlement; no failed read is
    # fabricated in the later decision-only attempts.
    missing_state = completion_adapters[-1].backend.get_task("missing-main-source")
    missing_settlements = [item for item in missing_state.attempt_settlements
                           if item["outcome"].startswith("Invalid completion decision:")]
    assert len(missing_settlements) == 3
    read_feedback = json.loads(missing_settlements[0]["outcome"].split("every required history source: ", 1)[1])
    assert read_feedback["missing_source_refs"] == [main_source]
    small = next(item for item in read_feedback["read_failures"] if item["status"] == "PAGE_TOO_SMALL")
    missing = next(item for item in read_feedback["read_failures"] if item["status"] == "MISSING")
    native_small = next(page for identity, args, page in completion_history_pages
                        if identity == "missing-main-source" and args.get("max_bytes") == 768)
    assert small["minimum_bytes"] == native_small["minimum_bytes"]
    assert small["reason"] == native_small["reason"]
    assert small["minimum_bytes"] > small["arguments"]["max_bytes"]
    assert small["retry_arguments"] == {
        **small["arguments"],
        "max_bytes": completion_adapters[-1].request_assembler.history_query_max_bytes,
    }
    assert small["minimum_bytes"] <= small["retry_arguments"]["max_bytes"]
    assert "retry_arguments" not in missing
    assert missing["arguments"]["source_ref"] != main_source

    # A Provider may return an unadvertised business read or delegation anyway.
    # Neither may reach a tool hook/worker/dispatch; legitimate history reads
    # before those requests remain functional and the repair budget is bounded.
    for forbidden_tool in ("sitina_read_file", "sitina_delegate_readonly"):
        for collection in (recorded, recorded_reasons, recorded_source_refs, prepared_goal_phases):
            collection.clear()
        forbidden_task = "forbidden-" + forbidden_tool
        forbidden_scripts = {
            "main": [[turn("Inspection summary ready.")]],
            "goal_completion": [
                [turn("", ProviderToolCall("out-of-scope", forbidden_tool, {"path": "private.txt"}))]
                for _ in range(3)
            ],
            "reviewer": [],
        }
        if task_kind == "readonly":
            forbidden_scripts["goal_interpretation"] = [[turn(provider_text)]]
        forbidden_runner, forbidden_clients, _ = runner_for(
            boundary_fixture(tmp_path / forbidden_task), forbidden_scripts,
        )
        forbidden_result = forbidden_runner.run(task_id=forbidden_task, task_kind=task_kind, goal=goal)
        assert forbidden_result["task"]["status"] == "STALLED"
        assert "permits only sitina_history_query" in forbidden_result["reason"]
        assert forbidden_task not in accepted_task_ids
        assert sum(role == "goal_completion" for role, _ in forbidden_clients) == 3
        dispatched = [name for identity, name, _ in completion_dispatches if identity == forbidden_task]
        hooks = [name for identity, name in completion_tool_hooks if identity == forbidden_task]
        assert dispatched and set(dispatched) == {"sitina_history_query"}
        assert hooks and set(hooks) == {"sitina_history_query"}

def test_reviewed_readonly_accepts_zero_diff_with_independent_review(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    scripts = {
        "main": [[turn("analysis complete")]],
        "reviewer": [[turn(json.dumps({
            "schema": "SITINA_LOOP_REVIEW_V1",
            "verdict": "PASS",
            "reason": "Verified.",
            "artifact_ref": "__ARTIFACT_REF__",
        }))]],
    }
    runner, clients, _keys = runner_for(boundary, scripts)

    result = runner.run(
        task_id="task-reviewed-readonly",
        task_kind="reviewed_readonly",
        goal="Inspect with independent review",
    )

    assert result["status"] == "succeeded"
    assert result["changed_paths"] == []
    assert result["review_status"] == "PASS"
    assert [role for role, _client in clients] == ["goal_interpretation", "main", "reviewer", "goal_completion"]
    assert result["task"]["status"] == "SUCCEEDED"


class BlockingClient(ScriptedMockToolClient):
    def __init__(self, entered: threading.Event, release: threading.Event, text: str):
        super().__init__([turn(text)])
        self.entered = entered
        self.release = release

    def complete_tool_turn(self, *args, **kwargs):
        self.entered.set()
        assert self.release.wait(10)
        return super().complete_tool_turn(*args, **kwargs)


class BlockSecondTurnClient(ScriptedMockToolClient):
    def __init__(self, entered: threading.Event, release: threading.Event):
        super().__init__([
            turn("", ProviderToolCall(
                "write-before-cancel",
                "sitina_edit_file",
                {"path": "value.txt", "old_string": "OLD", "new_string": "NEW"},
            )),
            turn("would have completed"),
        ])
        self.entered = entered
        self.release = release
        self.calls = 0

    def complete_tool_turn(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 2:
            self.entered.set()
            assert self.release.wait(10)
        return super().complete_tool_turn(*args, **kwargs)


@pytest.mark.parametrize(
    ("kind", "expected_status"),
    [("PAUSE", "paused"), ("CANCEL", "cancelled")],
)
def test_pause_and_cancel_are_accepted_during_provider_wait_before_commit(
    tmp_path: Path, kind: str, expected_status: str
) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    entered = threading.Event()
    release = threading.Event()

    def factory(_role: str, _adapter):
        if _adapter.work_purpose == "goal_interpretation":
            return scripted_factory(boundary, {})[0](_role, _adapter)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=BlockingClient(entered, release, "stale response"),
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    runner = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
    )
    output: dict[str, object] = {}

    def run_task() -> None:
        output.update(runner.run(task_id="task-control", task_kind="no_change", goal="wait"))

    thread = threading.Thread(target=run_task)
    thread.start()
    assert entered.wait(10)
    response = send_control_request(boundary.state_root, {
        "command": "input",
        "task_id": "task-control",
        "input_id": "control-1",
        "kind": kind,
        "body": kind.lower(),
    })
    assert response["status"] == "accepted"
    release.set()
    thread.join(15)
    assert not thread.is_alive()
    assert output["status"] == expected_status
    assert output["task"]["status"] == ("PAUSED" if kind == "PAUSE" else "CANCELLED")


def test_cancel_terminal_captures_completed_business_effect_without_success_commit(
    tmp_path: Path,
) -> None:
    boundary = boundary_fixture(tmp_path)
    boundary.business_workspace.mkdir(parents=True)
    (boundary.business_workspace / "value.txt").write_text("OLD", encoding="utf-8")
    keys = MemoryKeychainBackend()
    entered = threading.Event()
    release = threading.Event()

    def factory(role: str, _adapter):
        if _adapter.work_purpose == "goal_interpretation":
            return scripted_factory(boundary, {})[0](role, _adapter)
        assert role == "main"
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=BlockSecondTurnClient(entered, release),
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            approval_callback=lambda _request: True,
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
    output: dict[str, object] = {}
    thread = threading.Thread(target=lambda: output.update(runner.run(
        task_id="task-cancel-after-write",
        task_kind="code_change",
        goal="Change value.txt to NEW",
        check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('value.txt').is_file()"),
    )))
    thread.start()
    assert entered.wait(10)
    response = send_control_request(boundary.state_root, {
        "command": "input",
        "task_id": "task-cancel-after-write",
        "input_id": "cancel-after-write",
        "kind": "CANCEL",
        "body": "cancel",
    })
    assert response["status"] == "accepted"
    release.set()
    thread.join(20)
    assert not thread.is_alive()
    assert output["status"] == "cancelled"
    assert output["changed_paths"] == ["value.txt"]
    assert output["completed_effects_retained"] is True
    assert output["success_commit_cancelled"] is True
    assert len(output["completed_write_operation_ids"]) == 1
    assert (boundary.business_workspace / "value.txt").read_text() == "NEW"
    task = output["task"]
    assert task["artifact_version"] == 2
    assert task["artifact_ref"] == task["terminal_result"]["artifact_ref"]
    assert task["terminal_result"]["final_result"]["changed_paths"] == ["value.txt"]


def test_repeated_cancel_in_terminal_commit_gap_rebinds_and_commits_once(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    entered = threading.Event()
    release = threading.Event()
    injected = False

    def backend_factory(root: Path) -> LoopBackend:
        nonlocal injected
        backend = LoopBackend.open(root, keychain_backend=keys)
        original = backend.propose_terminal

        def propose_with_repeat_cancel(task_id, proposal, **kwargs):
            nonlocal injected
            if proposal.terminal_status.value == "CANCELLED" and not injected:
                injected = True
                backend.accept_input(
                    task_id,
                    input_id="repeat-cancel",
                    kind=InputKind.CANCEL,
                    body="cancel again",
                )
                backend.handle_next_input(task_id, affects_goal=False, affects_acceptance=False)
            return original(task_id, proposal, **kwargs)

        backend.propose_terminal = propose_with_repeat_cancel  # type: ignore[method-assign]
        return backend

    def factory(_role: str, _adapter):
        if _adapter.work_purpose == "goal_interpretation":
            return scripted_factory(boundary, {})[0](_role, _adapter)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=BlockingClient(entered, release, "stale response"),
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    runner = LoopTaskRunner(
        boundary,
        backend_factory=backend_factory,
        runtime_factory=factory,
    )
    output: dict[str, object] = {}
    thread = threading.Thread(target=lambda: output.update(runner.run(
        task_id="task-repeat-cancel",
        task_kind="no_change",
        goal="Wait for cancellation",
    )))
    thread.start()
    assert entered.wait(10)
    response = send_control_request(boundary.state_root, {
        "command": "input",
        "task_id": "task-repeat-cancel",
        "input_id": "first-cancel",
        "kind": "CANCEL",
        "body": "cancel",
    })
    assert response["status"] == "accepted"
    release.set()
    thread.join(20)
    assert not thread.is_alive()
    assert output["status"] == "cancelled"
    assert output["task"]["status"] == "CANCELLED"
    assert output["task"]["input_count"] == 2
    assert output["task"]["handled_input_seq"] == 2
    with LoopBackend.open(boundary.state_root, keychain_backend=keys) as reopened:
        terminal_events = [
            event
            for event in reopened.store.task_events("task-repeat-cancel")
            if event.event_type == "loop.task-terminated"
        ]
        assert len(terminal_events) == 1


def test_cancel_with_unknown_effect_returns_bounded_recovery_blocked_without_terminal_retry(
    tmp_path: Path,
) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    proposal_calls = 0

    def backend_factory(root: Path) -> LoopBackend:
        nonlocal proposal_calls
        backend = LoopBackend.open(root, keychain_backend=keys)
        original = backend.propose_terminal

        def counted_proposal(*args, **kwargs):
            nonlocal proposal_calls
            proposal_calls += 1
            return original(*args, **kwargs)

        backend.propose_terminal = counted_proposal  # type: ignore[method-assign]
        return backend

    class UnknownThenCancelRuntime:
        catalog = None
        max_turns = None
        no_provider_fixture = True

        def __init__(self, adapter: LoopOperationAdapter) -> None:
            self.adapter = adapter

        def run(self, *_args, **_kwargs):
            try:
                self.adapter.tool_call(
                    "unknown-before-cancel",
                    ProviderToolCall(
                        "unknown-write",
                        "sitina_write_file",
                        {"path": "unknown.txt", "content": "possibly written"},
                    ),
                    lambda: (_ for _ in ()).throw(RuntimeError("transport outcome unknown")),
                    permission="write",
                )
            except Exception as error:
                assert "unknown" in str(error)
            self.adapter.backend.accept_input(
                self.adapter.task_id,
                input_id="cancel-with-unknown",
                kind=InputKind.CANCEL,
                body="cancel",
            )
            self.adapter.backend.handle_next_input(
                self.adapter.task_id,
                affects_goal=False,
                affects_acceptance=False,
            )
            return {"terminal_state": "CANCELLED", "response": "cancelled with unknown effect"}

    runner = LoopTaskRunner(
        boundary,
        approve_writes=True,
        backend_factory=backend_factory,
        runtime_factory=lambda _role, adapter: (scripted_factory(boundary, {})[0](_role, adapter) if adapter.work_purpose == "goal_interpretation" else UnknownThenCancelRuntime(adapter)),  # type: ignore[arg-type]
    )
    result = runner.run(
        task_id="task-cancel-unknown",
        task_kind="code_change",
        goal="Attempt a write, then cancel",
        check_command=(sys.executable, "-c", "raise SystemExit(0)"),
    )
    assert result["status"] == "recovery_blocked"
    assert result["blocker_id"] == "cancel-unknown-operation-effect"
    assert len(result["unknown_effect_operation_ids"]) == 1
    assert result["task"]["status"] == "RECOVERY_BLOCKED"
    assert result["task"]["stop_report_ref"]
    assert result["task"]["terminal_event_id"] is None
    assert proposal_calls == 0


def test_correction_during_wait_invalidates_stale_provider_result_and_restarts(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    entered = threading.Event()
    release = threading.Event()
    clients: list[ScriptedMockToolClient] = []

    def factory(_role: str, _adapter):
        if _adapter.work_purpose == "goal_interpretation":
            state = _adapter.backend.get_task(_adapter.task_id)
            condition = "Old goal work is complete." if state.goal_version == 1 else "New corrected goal work is complete."
            return scripted_factory(boundary, {"goal_interpretation": [[turn(json.dumps({"goal_input": {
                "goal": "old goal" if state.goal_version == 1 else "new goal", "constraints": [],
                "acceptance_conditions": [condition], "missing_inputs": [], "question": None,
            }}))]]})[0](_role, _adapter)
        if _adapter.work_purpose == "goal_completion":
            return scripted_factory(boundary, {})[0](_role, _adapter)
        client = (
            BlockingClient(entered, release, "stale response")
            if not clients
            else ScriptedMockToolClient([turn("corrected response")])
        )
        clients.append(client)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    runner = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=factory,
    )
    output: dict[str, object] = {}
    thread = threading.Thread(
        target=lambda: output.update(runner.run(task_id="task-correct", task_kind="no_change", goal="old goal"))
    )
    thread.start()
    assert entered.wait(10)
    response = send_control_request(boundary.state_root, {
        "command": "input",
        "task_id": "task-correct",
        "input_id": "correction-1",
        "kind": "CORRECTION",
        "body": "new goal",
    })
    assert response["status"] == "accepted"
    release.set()
    thread.join(15)
    assert not thread.is_alive()
    assert output["status"] == "succeeded"
    assert output["task"]["goal_version"] == 2
    assert "new goal" in clients[1].received_messages[0][-1]["content"]
    corrected_context = json.loads(clients[1].received_messages[0][-1]["content"])["execution_context"]
    assert corrected_context["interpreted_goal_input"]["acceptance_conditions"] == ["New corrected goal work is complete."]
    assert corrected_context["goal_input_provenance"]["goal_boundary"]["input_seq"] == 1
    assert corrected_context["goal_input_provenance"]["goal_version"] == 2


def test_live_authority_rejects_a_second_owner_and_serves_status(tmp_path: Path) -> None:
    keys = MemoryKeychainBackend()
    root = tmp_path / "state"
    with LoopBackend.open(root, keychain_backend=keys) as backend:
        backend.create_task(
            task_id="task-one-authority",
            session_id="session",
            task_kind="no_change",
            goal="goal",
            required_outcome_ids=("outcome-1",),
            artifact_ref="cas:initial",
            environment_ref="fixture",
            capability_snapshot_id="fixture",
        )
        with LoopControlAuthority(backend, root):
            assert send_control_request(root, {"command": "status", "task_id": "task-one-authority"})["status"] == "ok"
            from sitina.cli import build_parser
            args = build_parser().parse_args([
                "loop-task", "retention", "--state-root", str(root), "--workspace", str(tmp_path),
                "--task-id", "task-one-authority", "--operation-id", "retention-test",
            ])
            assert args.action == "status"
            unavailable = send_control_request(root, {
                "command": "retention", "task_id": "task-one-authority",
                "action": "schedule", "operation_id": "retention-test", "memory_id": "memory-test",
            })
            assert unavailable == {
                "status": "error", "error_type": "TaskConflict",
                "reason": "native memory authority is unavailable",
            }
            rejected = send_control_request(root, {
                "command": "retention", "task_id": "task-one-authority",
                "operation_id": "retention-test", "force": True,
            })
            assert rejected == {
                "status": "error", "error_type": "LoopAuthorityError",
                "reason": "unknown retention control fields",
            }
            # Use the real native memory schema and Journal rollout. A task ID
            # is not itself a valid agent_private owner principal.
            import datetime as dt
            from sitina.compatibility.capabilities import FormatCapabilityRegistry
            from sitina.compatibility.feature_flags import FeatureActivationRegistry
            from sitina.compatibility.leases import CompatibilityLeaseRegistry, RuntimeCompatibilityLease
            from sitina.compatibility.rollout import JournalFeatureRollout
            from sitina.memory.native import MemoryACL, MemoryRepository

            now = dt.datetime.now(dt.timezone.utc)
            stamp = now.isoformat().replace('+00:00', 'Z')
            expiry = (now + dt.timedelta(minutes=5)).isoformat().replace('+00:00', 'Z')
            leases = CompatibilityLeaseRegistry(root)
            leases.register(RuntimeCompatibilityLease.build(
                process_id='retention-control-owner', binary_version='2.0.0',
                reader_capabilities=('memory-v1',), writer_capabilities=('memory-v1',),
                started_at=stamp, lease_expires_at=expiry, fencing_token=1,
            ))
            formats = FormatCapabilityRegistry.load(Path(__file__).resolve().parents[1] / 'config/format_capabilities.json')
            rollout = JournalFeatureRollout(backend.store.journal, leases, formats,
                process_id='retention-control-owner', fencing_token=1, binary_version='2.0.0',
                actor='user', goal_thread_id='task-one-authority')
            rollout.prepare('memory_v1_write', required_reader_capabilities=('memory-v1',), occurred_at=stamp)
            rollout.activate('memory_v1_write', occurred_at=stamp)
            repository = MemoryRepository(backend.store.journal, backend.store.cas, backend.context.provider,
                feature_activations=FeatureActivationRegistry.from_journal_events(backend.store.journal.iter_events(0)))
            memory = repository.create_candidate(memory_id='memory-retention-owner',
                scope='agent_private', owner_id='agent/task-one-authority',
                namespace='agent/task-one-authority/private', content='private retention input',
                source_event_ids=(), source_run_ids=(), evidence_refs=(), confidence=0.5,
                sensitivity='restricted', valid_from=stamp, expires_at=expiry,
                retention_policy='until-expired', supersedes=(),
                acl=MemoryACL(readers=('user',), writers=('user',), reviewers=('user',)), actor='user')
            backend.bind_memory_repository(repository, actor='user')
            scheduled = send_control_request(root, {
                'command': 'retention', 'task_id': 'task-one-authority', 'action': 'schedule',
                'operation_id': 'retention-owner-valid', 'memory_id': memory.memory_id,
            })
            assert scheduled['status'] == 'ok'
            assert scheduled['retention']['state'] == 'SCHEDULED'
            assert scheduled['retention']['physical_delete_executed'] is False
            status = send_control_request(root, {
                'command': 'retention', 'task_id': 'task-one-authority', 'action': 'status',
                'operation_id': 'retention-owner-valid',
            })
            assert status['retention']['state'] == 'SCHEDULED'
            backend.create_task(task_id='task-other-owner', session_id='session-other',
                task_kind='no_change', goal='other goal', required_outcome_ids=('outcome-1',),
                artifact_ref='cas:initial-other', environment_ref='fixture', capability_snapshot_id='fixture')
            denied = send_control_request(root, {
                'command': 'retention', 'task_id': 'task-other-owner', 'action': 'status',
                'operation_id': 'retention-owner-valid',
            })
            assert denied == {'status': 'error', 'error_type': 'TaskConflict',
                'reason': "retention control is limited to this task's private memory"}
            with pytest.raises(Exception, match="another live coordinator"):
                LoopControlAuthority(backend, root).start()


def test_control_authority_survives_disconnected_and_partial_clients(tmp_path: Path) -> None:
    keys = MemoryKeychainBackend()
    root = tmp_path / "state"
    with LoopBackend.open(root, keychain_backend=keys) as backend:
        backend.create_task(
            task_id="task-resilient-control",
            session_id="session",
            task_kind="no_change",
            goal="goal",
            required_outcome_ids=("outcome-1",),
            artifact_ref="cas:initial",
            environment_ref="fixture",
            capability_snapshot_id="fixture",
        )
        with LoopControlAuthority(backend, root) as authority:
            disconnected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            disconnected.connect(str(authority.socket_path))
            disconnected.sendall(json.dumps({"command": "status", "task_id": "task-resilient-control"}).encode() + b"\n")
            disconnected.close()
            partial = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            partial.connect(str(authority.socket_path))
            partial.sendall(b'{"command":')
            partial.close()
            assert send_control_request(
                root, {"command": "status", "task_id": "task-resilient-control"}
            )["status"] == "ok"


def test_authority_lease_blocks_runner_before_persistent_or_business_initialization(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    runner, _clients, _keys = runner_for(boundary, {"main": [[turn("unused")]], "reviewer": []})
    with LoopAuthorityLease(boundary.state_root):
        with pytest.raises(Exception, match="another live coordinator"):
            runner.run(task_id="task-race", task_kind="no_change", goal="must not start")
        assert not (boundary.state_root / ".sitina-session-runtime-v1").exists()
        assert not (boundary.state_root / "provider-home").exists()
        assert not boundary.business_workspace.exists()


def test_old_loop_state_cli_obeys_lock_even_before_control_socket_exists(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DevelopmentBoundary, "validate", classmethod(lambda cls, **kwargs: object()))
    root = tmp_path / "locked-state"
    with LoopAuthorityLease(root):
        status = cmd_loop_state(argparse.Namespace(loop_state_cmd="initialize", state_root=str(root)))
    output = json.loads(capsys.readouterr().out)
    assert status == 3
    assert output["new_coordinator_opened"] is False
    assert not (root / ".sitina-session-runtime-v1").exists()


def test_old_loop_state_cli_rejects_outside_state_before_directory_or_lock_creation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    import sitina.cli as cli
    boundary = boundary_fixture(tmp_path)
    monkeypatch.setattr(cli, "SITINA_HOME", boundary.source_root)
    monkeypatch.setenv("SITINA_HOME", str(boundary.source_root))
    monkeypatch.setenv("SITINA_R4_DEV_ROOT", str(boundary.source_root))
    monkeypatch.setenv("SITINA_PYTHON", str(boundary.interpreter))
    outside = tmp_path / "outside-state"
    status = cmd_loop_state(argparse.Namespace(loop_state_cmd="initialize", state_root=str(outside)))
    output = json.loads(capsys.readouterr().out)
    assert status == 3
    assert output["state_root_created"] is False
    assert output["new_coordinator_opened"] is False
    assert not outside.exists()


def test_isolated_program_check_cannot_modify_business_artifact_or_escape(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    boundary.business_workspace.mkdir(parents=True)
    source = boundary.business_workspace / "result.txt"
    source.write_text("immutable", encoding="utf-8")
    escaped = tmp_path / "escaped.txt"
    outside_input = tmp_path / "outside-input"
    outside_input.mkdir()
    private_source = outside_input / "private.txt"
    private_source.write_text("outside-private-data", encoding="utf-8")
    private_mode = private_source.stat().st_mode
    (boundary.business_workspace / "escape-link.txt").symlink_to(private_source)
    (boundary.business_workspace / "escape-directory").symlink_to(outside_input, target_is_directory=True)
    (boundary.business_workspace / "dangling-link").symlink_to(tmp_path / "absent-input")
    keys = MemoryKeychainBackend()
    with LoopAuthorityLease(boundary.state_root):
        with LoopBackend.open(boundary.state_root, keychain_backend=keys) as backend:
            initial = backend.context_memory.persist(
                {"schema": "TEST_ARTIFACT", "snapshot": _workspace_snapshot(boundary.business_workspace)},
                purpose="test-artifact",
            )
            backend.create_task(
                task_id="task-check-isolation",
                session_id="session",
                task_kind="code_change",
                goal="keep source immutable during check",
                required_outcome_ids=("outcome-1",),
                artifact_ref=initial.reference_id,
                environment_ref="fixture",
                capability_snapshot_id="fixture",
            )
            runner = LoopTaskRunner(boundary)
            program, _ref, _adapter = runner._program_check(
                backend,
                "task-check-isolation",
                (
                    sys.executable,
                    "-c",
                    (
                        "from pathlib import Path; "
                        f"Path({str(source)!r}).write_text('changed'); "
                        f"Path({str(escaped)!r}).write_text('escaped')"
                    ),
                ),
                _workspace_snapshot(boundary.business_workspace),
            )
            assert program["sandbox"] == "macos-seatbelt-check-copy-v1"
            assert int(program["exit_code"]) != 0
            assert source.read_text() == "immutable"
            assert not escaped.exists()
            assert private_source.read_text() == "outside-private-data"
            assert private_source.stat().st_mode == private_mode
            check_roots = list((boundary.state_root / "checks").iterdir())
            assert len(check_roots) == 1
            check_input = check_roots[0] / "input"
            assert _workspace_snapshot(check_input) == _workspace_snapshot(boundary.business_workspace)
            for name in ("escape-link.txt", "escape-directory", "dangling-link"):
                assert not (check_input / name).exists()
                assert not (check_input / name).is_symlink()


def test_correction_during_program_check_forces_new_goal_and_recheck(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    clients: list[ScriptedMockToolClient] = []
    scripts = [
        [
            turn("", ProviderToolCall("w1", "sitina_write_file", {"path": "result.txt", "content": "OLD"})),
            turn("old complete"),
        ],
        [
            turn("", ProviderToolCall("w2", "sitina_edit_file", {"path": "result.txt", "old_string": "OLD", "new_string": "NEW"})),
            turn("new complete"),
        ],
    ]

    def factory(role: str, _adapter):
        if _adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return scripted_factory(boundary, {})[0](role, _adapter)
        if role == "reviewer":
            client = ScriptedMockToolClient([])
            evidence_requested = False

            def review(*_args, messages, **_kwargs):
                nonlocal evidence_requested
                if not evidence_requested:
                    evidence_requested = True
                    return reviewer_evidence_turn(messages, call_prefix="check-correction-proof")
                return turn(json.dumps(review_v2_document(
                    messages, verdict="PASS", reason="verified"
                )))

            client.complete_tool_turn = review  # type: ignore[method-assign]
        else:
            client = ScriptedMockToolClient(scripts.pop(0))
            clients.append(client)
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
    command = (
        sys.executable,
        "-c",
        (
            "import os,time; from pathlib import Path; "
            "out=Path(os.environ['SITINA_CHECK_OUTPUT']); "
            "value=Path('result.txt').read_text(); "
            "(out/'entered').write_text(value); "
            "deadline=time.time()+10; "
            "exec(\"while value == 'OLD' and not (out/'release').exists() and time.time() < deadline:\\n time.sleep(.02)\"); "
            "assert value in {'OLD','NEW'}"
        ),
    )
    output: dict[str, object] = {}
    thread = threading.Thread(
        target=lambda: output.update(
            runner.run(task_id="task-check-correction", task_kind="code_change", goal="produce OLD", check_command=command)
        )
    )
    thread.start()
    entered: Path | None = None
    deadline = time.time() + 10
    while time.time() < deadline and entered is None:
        matches = list((boundary.state_root / "checks").glob("*/output/entered"))
        if matches:
            entered = matches[0]
            break
        time.sleep(0.02)
    assert entered is not None
    response = send_control_request(boundary.state_root, {
        "command": "input",
        "task_id": "task-check-correction",
        "input_id": "correction-during-check",
        "kind": "CORRECTION",
        "body": "produce NEW",
    })
    assert response["status"] == "accepted"
    (entered.parent / "release").write_text("go", encoding="utf-8")
    thread.join(20)
    assert not thread.is_alive()
    assert output["status"] == "succeeded"
    assert output["task"]["goal_version"] == 2
    assert (boundary.business_workspace / "result.txt").read_text() == "NEW"
    assert "produce NEW" in clients[1].received_messages[0][-1]["content"]


def test_correction_during_independent_review_invalidates_old_review_and_restarts(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    entered = threading.Event()
    release = threading.Event()
    main_clients: list[ScriptedMockToolClient] = []
    main_scripts = [
        [
            turn("", ProviderToolCall("w1", "sitina_write_file", {"path": "result.txt", "content": "OLD"})),
            turn("old result"),
        ],
        [
            turn("", ProviderToolCall("w2", "sitina_edit_file", {"path": "result.txt", "old_string": "OLD", "new_string": "NEW"})),
            turn("new result"),
        ],
    ]
    review_count = 0

    def factory(role: str, _adapter):
        nonlocal review_count
        if _adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return scripted_factory(boundary, {})[0](role, _adapter)
        if role == "main":
            client = ScriptedMockToolClient(main_scripts.pop(0))
            main_clients.append(client)
        else:
            review_count += 1
            client = ScriptedMockToolClient([])
            evidence_requested = False

            def review(*_args, messages, **_kwargs):
                nonlocal evidence_requested
                if not evidence_requested:
                    evidence_requested = True
                    if review_count == 1:
                        entered.set()
                        assert release.wait(10)
                    return reviewer_evidence_turn(messages, call_prefix=f"review-correction-{review_count}")
                return turn(json.dumps(review_v2_document(
                    messages, verdict="PASS", reason="bound review"
                )))

            client.complete_tool_turn = review  # type: ignore[method-assign]
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
    output: dict[str, object] = {}
    thread = threading.Thread(target=lambda: output.update(runner.run(
        task_id="task-review-correction",
        task_kind="code_change",
        goal="produce OLD",
        check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('result.txt').is_file()"),
    )))
    thread.start()
    assert entered.wait(10)
    response = send_control_request(boundary.state_root, {
        "command": "input",
        "task_id": "task-review-correction",
        "input_id": "correction-during-review",
        "kind": "CORRECTION",
        "body": "produce NEW",
    })
    assert response["status"] == "accepted"
    release.set()
    thread.join(20)
    assert not thread.is_alive()
    assert output["status"] == "succeeded"
    assert output["task"]["goal_version"] == 2
    assert (boundary.business_workspace / "result.txt").read_text() == "NEW"
    assert "produce NEW" in main_clients[1].received_messages[0][-1]["content"]


def test_four_no_progress_attempts_dock_stalled_even_when_wording_changes(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    responses = iter(["wording one", "wording two", "wording three", "wording four"])

    class FailedRuntime:
        no_provider_fixture = True

        catalog = None
        max_turns = None

        def run(self, *_args, **_kwargs):
            return {"terminal_state": "FAILED", "response": next(responses)}

    runner = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=lambda _role, _adapter: (scripted_factory(boundary, {})[0](_role, _adapter) if _adapter.work_purpose == "goal_interpretation" else FailedRuntime()),  # type: ignore[arg-type]
    )
    result = runner.run(task_id="task-stalled", task_kind="no_change", goal="goal")
    assert result["status"] == "stalled"
    assert result["task"]["status"] == "STALLED"
    assert result["settled_attempt_count"] == 4


def test_three_review_disagreements_wait_for_input_despite_rewording_and_unrelated_edits(
    tmp_path: Path,
) -> None:
    boundary = boundary_fixture(tmp_path)
    scripts = {
        "main": [
            [
                turn("", ProviderToolCall("w1", "sitina_write_file", {"path": "artifact.txt", "content": "core"})),
                turn("candidate one"),
            ],
            [
                turn("", ProviderToolCall("w2", "sitina_write_file", {"path": "unrelated-1.txt", "content": "noise"})),
                turn("candidate two"),
            ],
            [
                turn("", ProviderToolCall("w3", "sitina_write_file", {"path": "unrelated-2.txt", "content": "more noise"})),
                turn("candidate three"),
            ],
        ],
        "reviewer": [
            [turn(json.dumps({"schema": "SITINA_LOOP_REVIEW_V1", "verdict": "BLOCK", "reason": "issue phrasing one", "artifact_ref": "__ARTIFACT_REF__"}))],
            [turn(json.dumps({"schema": "SITINA_LOOP_REVIEW_V1", "verdict": "NEEDS_EVIDENCE", "reason": "same unresolved issue phrased differently", "artifact_ref": "__ARTIFACT_REF__"}))],
            [turn("malformed review before the third disagreement")],
            [turn(json.dumps({"schema": "SITINA_LOOP_REVIEW_V1", "verdict": "BLOCK", "reason": "third wording of unresolved issue", "artifact_ref": "__ARTIFACT_REF__"}))],
        ],
    }
    runner, _clients, _keys = runner_for(boundary, scripts)
    from tests.test_loop_batch_3a_host import _context

    boundary.business_workspace.mkdir(parents=True, exist_ok=True)
    with LoopAuthorityLease(boundary.state_root) as admission_lease:
        admission_backend = runner.backend_factory(boundary.state_root)
        try:
            with LoopControlAuthority(admission_backend, boundary.state_root, lease=admission_lease):
                admitted, created = admission_backend.admit_task(
                    task_id="task-review-wait", session_id="session-durable-review",
                    submission_id="submission-durable-review", task_kind="code_change",
                    goal="create artifact.txt", workspace_path=str(boundary.business_workspace),
                    check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('artifact.txt').read_text() == 'core'"),
                    provider_profile="mock", approve_writes=True, **_context(),
                )
                assert created and admitted.descriptor_ref and admitted.descriptor_hash
                result = runner.run_existing(
                    admission_backend, task_id="task-review-wait", task_kind="code_change",
                    check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('artifact.txt').read_text() == 'core'"),
                )
        finally:
            admission_backend.close()
    assert result["status"] == "waiting_input"
    assert result["task"]["status"] == "WAITING_INPUT"
    assert result["settled_attempt_count"] == 3
    assert result["blocker_id"] == "review-disagreement:outcome-1"

    # Resume the same durable candidate after a persisted local protocol repair.
    from sitina.loop.recovery import RecoveryCoordinator

    scripts["reviewer"].extend([
        [turn("malformed resumed review")],
        [turn("malformed final bounded repair")],
    ])
    with LoopAuthorityLease(boundary.state_root) as lease:
        resumed_backend = runner.backend_factory(boundary.state_root)
        try:
            with LoopControlAuthority(resumed_backend, boundary.state_root, lease=lease):
                before = resumed_backend.get_task("task-review-wait")
                assert [item["repair_index"] for item in before.review_repairs] == [1]
                original_artifact = before.artifact_ref
                repair_binding = (
                    before.review_repairs[0]["review_subject_lineage"],
                    before.review_repairs[0]["artifact_ref"],
                )
                assert repair_binding[1] == original_artifact
                assert not before.is_terminal
                resume_requested = resumed_backend.request_resume(
                    "task-review-wait",
                    resume_request_id='durable-review-repair-continuation',
                    expected_task_revision=resumed_backend.get_task("task-review-wait").task_revision,
                )
                resume_request_observation = {
                    "status": resume_requested.status.value,
                    "recovery_state": resume_requested.recovery_state,
                    "resume_request_id": resume_requested.resume_request_id,
                    "task_revision": resume_requested.task_revision,
                }
                assert resume_requested.resume_request_id == 'durable-review-repair-continuation', resume_request_observation
                recovered = RecoveryCoordinator(resumed_backend).recover("task-review-wait", explicit_resume=True)
                assert recovered.recovery_state == "READY_RECOVERED", (
                    recovered.status.value, recovered.recovery_state,
                    recovered.resume_request_id, resume_request_observation,
                )
                resumed = runner.run_existing(
                    resumed_backend, task_id="task-review-wait", task_kind="code_change",
                    check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('artifact.txt').read_text() == 'core'"),
                )
                assert resumed["status"] == "waiting_input"
                assert resumed["blocker_id"] == "review-protocol-repair:outcome-1"
                current = resumed_backend.get_task("task-review-wait")
                assert current.artifact_ref == original_artifact
                assert [item["repair_index"] for item in current.review_repairs] == [1, 2, 3]
                assert {(item["review_subject_lineage"], item["artifact_ref"]) for item in current.review_repairs} == {repair_binding}
                assert not current.is_terminal
                assert len([client for role, client in _clients if role == "main"]) == 3
                review_count = len([client for role, client in _clients if role == "reviewer"])
                exhausted_resume_requested = resumed_backend.request_resume(
                    "task-review-wait",
                    resume_request_id='durable-review-budget-exhausted-continuation',
                    expected_task_revision=resumed_backend.get_task("task-review-wait").task_revision,
                )
                exhausted_resume_observation = {
                    "status": exhausted_resume_requested.status.value,
                    "recovery_state": exhausted_resume_requested.recovery_state,
                    "resume_request_id": exhausted_resume_requested.resume_request_id,
                    "task_revision": exhausted_resume_requested.task_revision,
                }
                assert exhausted_resume_requested.resume_request_id == 'durable-review-budget-exhausted-continuation', exhausted_resume_observation
                exhausted_recovered = RecoveryCoordinator(resumed_backend).recover("task-review-wait", explicit_resume=True)
                assert exhausted_recovered.recovery_state == "READY_RECOVERED", (
                    exhausted_recovered.status.value, exhausted_recovered.recovery_state,
                    exhausted_recovered.resume_request_id, exhausted_resume_observation,
                )
                exhausted = runner.run_existing(
                    resumed_backend, task_id="task-review-wait", task_kind="code_change",
                    check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('artifact.txt').read_text() == 'core'"),
                )
                assert exhausted["blocker_id"] == "review-protocol-repair:outcome-1"
                assert len([client for role, client in _clients if role == "reviewer"]) == review_count
        finally:
            resumed_backend.close()


def test_correction_in_acceptance_commit_gap_invalidates_old_result(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    clients: list[ScriptedMockToolClient] = []
    original_record = None
    injected = False

    def backend_factory(root: Path) -> LoopBackend:
        nonlocal original_record, injected
        backend = LoopBackend.open(root, keychain_backend=keys)
        original_record = backend.record_acceptance

        def record_with_correction(task_id, submission, **kwargs):
            nonlocal injected
            if not injected:
                injected = True
                backend.accept_input(
                    task_id,
                    input_id="commit-gap-correction",
                    kind=InputKind.CORRECTION,
                    body="new commit requirement",
                )
                backend.handle_next_input(task_id, affects_goal=True, affects_acceptance=True)
            return original_record(task_id, submission, **kwargs)

        backend.record_acceptance = record_with_correction  # type: ignore[method-assign]
        return backend

    def factory(_role: str, _adapter):
        if _adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return scripted_factory(boundary, {})[0](_role, _adapter)
        text = "old result" if not clients else "new result"
        client = ScriptedMockToolClient([turn(text)])
        clients.append(client)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    runner = LoopTaskRunner(boundary, backend_factory=backend_factory, runtime_factory=factory)
    result = runner.run(task_id="task-commit-gap", task_kind="no_change", goal="old requirement")
    assert result["status"] == "succeeded"
    assert result["task"]["goal_version"] == 2
    assert result["task"]["acceptance_version"] >= 3
    assert "new commit requirement" in clients[1].received_messages[0][-1]["content"]


def test_artifact_change_after_review_forces_rework_and_new_verification(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    main_scripts = [
        [
            turn("", ProviderToolCall("w1", "sitina_write_file", {"path": "result.txt", "content": "v1"})),
            turn("v1 complete"),
        ],
        [
            turn("", ProviderToolCall("w2", "sitina_edit_file", {"path": "result.txt", "old_string": "tampered", "new_string": "v2"})),
            turn("v2 complete"),
        ],
    ]
    review_count = 0

    def factory(role: str, _adapter):
        nonlocal review_count
        if _adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return scripted_factory(boundary, {})[0](role, _adapter)
        if role == "main":
            client = ScriptedMockToolClient(main_scripts.pop(0))
        else:
            review_count += 1
            client = ScriptedMockToolClient([])
            evidence_requested = False

            def review(*_args, messages, **_kwargs):
                nonlocal evidence_requested
                if not evidence_requested:
                    evidence_requested = True
                    return reviewer_evidence_turn(messages, call_prefix=f"artifact-change-{review_count}")
                if review_count == 1:
                    (boundary.business_workspace / "result.txt").write_text("tampered", encoding="utf-8")
                return turn(json.dumps(review_v2_document(
                    messages, verdict="PASS", reason="review response"
                )))

            client.complete_tool_turn = review  # type: ignore[method-assign]
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
        task_id="task-review-mutation",
        task_kind="code_change",
        goal="produce verified result",
        check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('result.txt').is_file()"),
    )
    assert result["status"] == "succeeded"
    assert result["cycle"] == 2
    assert (boundary.business_workspace / "result.txt").read_text() == "v2"


def test_more_than_four_tool_calls_do_not_trigger_business_attempt_limit(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    calls = tuple(
        ProviderToolCall(f"r{index}", "sitina_list_directory", {"path": str(boundary.business_workspace)})
        for index in range(5)
    )
    runner, clients, keys = runner_for(
        boundary, {"main": [[turn("", *calls), turn("complete")]], "reviewer": []}
    )
    result = runner.run(task_id="task-many-tools", task_kind="no_change", goal="inspect repeatedly")
    assert result["status"] == "succeeded"
    # Completion evaluation adds its own Provider turns and history reads.
    # Count only this test's business work, rather than the whole task.
    main_clients = [client for role, client in clients if role == "main"]
    assert len(main_clients) == 1
    assert len(main_clients[0].received_messages) == 2
    expected_call_ids = {call.call_id for call in calls}
    backend = LoopBackend.open(boundary.state_root, keychain_backend=keys)
    try:
        task = backend.get_task("task-many-tools")
        business_tools = [
            operation for operation in task.operations.values()
            if operation.logical_operation_id.rsplit(":", 1)[-1] in expected_call_ids
        ]
        assert len(business_tools) == len(calls)
        assert {operation.logical_operation_id.rsplit(":", 1)[-1] for operation in business_tools} == expected_call_ids
        assert all(operation.effect_status.name == "SUCCEEDED" for operation in business_tools)
    finally:
        backend.close()


@pytest.mark.parametrize("task_kind", ["readonly", "no_change"])
def test_non_mutating_task_denies_write_before_effect_even_when_cli_approval_is_enabled(
    tmp_path: Path, task_kind: str
) -> None:
    boundary = boundary_fixture(tmp_path)
    runner, _clients, keys = runner_for(
        boundary,
        {
            "main": [[
                turn("", ProviderToolCall(
                    "inspect-directory", "sitina_list_directory", {"path": "."},
                )),
                turn("", ProviderToolCall(
                    "forbidden-write",
                    "sitina_write_file",
                    {"path": "must-not-exist.txt", "content": "forbidden"},
                )),
                turn("inspection complete without mutation"),
            ]],
            "reviewer": [],
        },
    )
    result = runner.run(
        task_id=f"task-denied-{task_kind}",
        task_kind=task_kind,
        goal="Do not modify the workspace",
    )
    assert result["status"] == "succeeded"
    assert result["changed_paths"] == []
    assert not (boundary.business_workspace / "must-not-exist.txt").exists()
    with LoopBackend.open(boundary.state_root, keychain_backend=keys) as reopened:
        denied = [
            operation
            for operation in reopened.get_task(f"task-denied-{task_kind}").operations.values()
            if operation.effect_status is not None and operation.effect_status.value == "FAILED"
        ]
        assert len(denied) == 1
        document = reopened.context_memory.read(str(denied[0].result_ref))
        assert document["result"]["reason"] == f"{task_kind} task forbids business mutations"
        from sitina.loop.task_runtime import LoopContextIndex, _completion_business_evidence

        current = reopened.get_task(f"task-denied-{task_kind}")
        index = LoopContextIndex(reopened.store, current.task_id)
        evidence = _completion_business_evidence(
            current, index,
            {"acceptance_conditions": [
                "The requested write was denied.",
                "Read must-not-exist.txt.",
            ]},
            _workspace_snapshot(boundary.business_workspace),
            boundary.business_workspace,
        )
        failed_facts = [
            fact for fact in evidence["business_facts"]
            if fact["status"] == "FAILED"
        ]
        assert len(failed_facts) == 1
        fact = failed_facts[0]
        assert fact["observation_kind"] == "FAILED_TOOL_ATTEMPT"
        assert fact["operation_id"] == denied[0].operation_id
        assert fact["submitted_arguments"]["path"] == "must-not-exist.txt"
        assert any(entry.source_ref == fact["request_source_ref"] and entry.kind == "operation_result"
                   for entry in index.entries)
        assert fact["content_objects"] == []
        assert fact["reason"] == f"{task_kind} task forbids business mutations"
        assert evidence["completed_sources"] == []
        assert evidence["condition_observations"][0]["host_observation_satisfied"] is None
        assert evidence["condition_observations"][1]["host_observation_satisfied"] is False
        directory_facts = [item for item in evidence["business_facts"]
                           if item["status"] == "SUCCEEDED" and item["tool"] == "sitina_list_directory"]
        assert len(directory_facts) == 1
        directory = directory_facts[0]
        assert directory["submitted_arguments"] == {"path": "."}
        assert directory["content_objects"] == []
        assert any(entry.source_ref == directory["request_source_ref"]
                   and entry.kind == "operation_result" for entry in index.entries)
        assert directory["source_ref"] != directory["request_source_ref"]



def test_initially_correct_code_task_accepts_zero_diff_after_check_and_review(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    boundary.business_workspace.mkdir(parents=True)
    (boundary.business_workspace / "answer.py").write_text("ANSWER = 42\n", encoding="utf-8")
    runner, _clients, _keys = runner_for(
        boundary,
        {
            "main": [[turn("The implementation already satisfies the requirement.")]],
            "reviewer": [[turn(json.dumps({
                "schema": "SITINA_LOOP_REVIEW_V1",
                "verdict": "PASS",
                "reason": "The bound artifact is already correct.",
                "artifact_ref": "__ARTIFACT_REF__",
            }))]],
        },
    )
    result = runner.run(
        task_id="task-initially-correct",
        task_kind="code_change",
        goal="Ensure answer.py defines ANSWER = 42",
        check_command=(sys.executable, "-c", "import answer; assert answer.ANSWER == 42"),
    )
    assert result["status"] == "succeeded"
    assert result["changed_paths"] == []
    assert result["preflight_check"]["program_status"] == "PASS"
    assert result["program_check"]["program_status"] == "PASS"
    assert result["review_status"] == "PASS"
    assert result["shared_contract_evaluation"]["outcome"] == "CASE_PASS"


def test_unsupported_program_executor_is_not_run_and_waits_for_input(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()

    def must_not_start_runtime(_role: str, _adapter):
        raise AssertionError("model runtime must not start without executable check evidence")

    runner = LoopTaskRunner(
        boundary,
        backend_factory=lambda root: LoopBackend.open(root, keychain_backend=keys),
        runtime_factory=must_not_start_runtime,  # type: ignore[arg-type]
    )
    result = runner.run(
        task_id="task-unsupported-check",
        task_kind="code_change",
        goal="Run an unsupported check",
        check_command=("/bin/sh", "-c", "exit 0"),
    )
    assert result["status"] == "waiting_input"
    assert result["cycle"] == 1
    assert result["blocker_id"] == "program-check-executor-unavailable"
    assert result["settled_attempt_count"] == 1
    with LoopBackend.open(boundary.state_root, keychain_backend=keys) as reopened:
        settlement = reopened.get_task("task-unsupported-check").attempt_settlements[0]
        evidence = reopened.context_memory.read(settlement["evidence_refs"][0])
        assert evidence["result"]["program_status"] == "NOT_RUN"
        assert evidence["result"]["execution_started"] is False


def test_correction_after_context_projection_is_not_attached_to_stale_prompt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    clients: list[ScriptedMockToolClient] = []
    holder: dict[str, LoopBackend] = {}

    def backend_factory(root: Path) -> LoopBackend:
        backend = LoopBackend.open(root, keychain_backend=keys)
        holder["backend"] = backend
        return backend

    def factory(_role: str, _adapter):
        if _adapter.work_purpose in {"goal_interpretation", "goal_completion"}:
            return scripted_factory(boundary, {})[0](_role, _adapter)
        client = ScriptedMockToolClient([turn("response for corrected goal")])
        clients.append(client)
        home = boundary.state_root / "provider-home"
        return AutonomousRuntime(
            home,
            manager=ExtensionManager(home),
            client=client,
            profile=ProviderProfile("mock", "mock://offline", "", "scripted"),
            workspace=boundary.business_workspace,
            max_turns=None,
            strict_workspace=True,
        )

    runner = LoopTaskRunner(boundary, backend_factory=backend_factory, runtime_factory=factory)
    original = LoopRequestAssembler.prepare
    injected = False

    def prepare_with_correction(assembler, *args, **kwargs):
        nonlocal injected
        result = original(assembler, *args, **kwargs)
        if not injected and assembler.execution_context.get("goal_input_only") is not True:
            injected = True
            backend = holder["backend"]
            task_id = "task-goal-gap"
            backend.accept_input(
                task_id,
                input_id="goal-read-gap",
                kind=InputKind.CORRECTION,
                body="NEW requirement",
            )
            backend.handle_next_input(task_id, affects_goal=True, affects_acceptance=True)
        return result

    monkeypatch.setattr(LoopRequestAssembler, "prepare", prepare_with_correction)
    result = runner.run(task_id="task-goal-gap", task_kind="no_change", goal="OLD requirement")
    assert result["status"] == "succeeded"
    assert result["cycle"] == 2
    assert len(clients) == 2
    assert clients[0].received_messages == []
    prompt = str(clients[1].received_messages[0][0]["content"])
    assert "NEW requirement" in prompt


def test_correction_before_program_adapter_invalidates_main_evidence(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    boundary.business_workspace.mkdir(parents=True)
    (boundary.business_workspace / "result.txt").write_text("OLD", encoding="utf-8")
    keys = MemoryKeychainBackend()
    scripts = {
        "main": [
            [turn("OLD evidence")],
            [
                turn("", ProviderToolCall(
                    "replace-after-check-gap",
                    "sitina_edit_file",
                    {"path": "result.txt", "old_string": "OLD", "new_string": "NEW"},
                )),
                turn("NEW evidence"),
            ],
        ],
        "reviewer": [[turn(json.dumps({
            "schema": "SITINA_LOOP_REVIEW_V1",
            "verdict": "PASS",
            "reason": "Verified corrected artifact.",
            "artifact_ref": "__ARTIFACT_REF__",
        }))]],
    }
    factory, clients = scripted_factory(boundary, scripts)
    holder: dict[str, LoopBackend] = {}

    def backend_factory(root: Path) -> LoopBackend:
        backend = LoopBackend.open(root, keychain_backend=keys)
        holder["backend"] = backend
        return backend

    runner = LoopTaskRunner(
        boundary,
        approve_writes=True,
        backend_factory=backend_factory,
        runtime_factory=factory,
    )
    original = runner._program_check
    injected = False

    def check_with_correction(*args, **kwargs):
        nonlocal injected
        if kwargs.get("bound_task") is not None and not injected:
            injected = True
            backend = holder["backend"]
            backend.accept_input(
                "task-check-gap",
                input_id="program-adapter-gap",
                kind=InputKind.CORRECTION,
                body="result.txt must contain NEW",
            )
            backend.handle_next_input("task-check-gap", affects_goal=True, affects_acceptance=True)
        return original(*args, **kwargs)

    runner._program_check = check_with_correction  # type: ignore[method-assign]
    result = runner.run(
        task_id="task-check-gap",
        task_kind="code_change",
        goal="Keep result.txt as OLD",
        check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('result.txt').is_file()"),
    )
    assert result["status"] == "succeeded"
    assert result["cycle"] == 2
    assert (boundary.business_workspace / "result.txt").read_text() == "NEW"
    second_main = [client for role, client in clients if role == "main"][1]
    assert "result.txt must contain NEW" in str(second_main.received_messages[0][-1]["content"])


def test_correction_after_review_verdict_invalidates_reviewed_binding(tmp_path: Path) -> None:
    boundary = boundary_fixture(tmp_path)
    keys = MemoryKeychainBackend()
    scripts = {
        "main": [
            [
                turn("", ProviderToolCall("old-write", "sitina_write_file", {"path": "result.txt", "content": "OLD"})),
                turn("OLD evidence"),
            ],
            [
                turn("", ProviderToolCall(
                    "new-write",
                    "sitina_edit_file",
                    {"path": "result.txt", "old_string": "OLD", "new_string": "NEW"},
                )),
                turn("NEW evidence"),
            ],
        ],
        "reviewer": [
            [turn(json.dumps({
                "schema": "SITINA_LOOP_REVIEW_V1",
                "verdict": "PASS",
                "reason": "First bound review.",
                "artifact_ref": "__ARTIFACT_REF__",
            }))],
            [turn(json.dumps({
                "schema": "SITINA_LOOP_REVIEW_V1",
                "verdict": "PASS",
                "reason": "Corrected bound review.",
                "artifact_ref": "__ARTIFACT_REF__",
            }))],
        ],
    }
    factory, clients = scripted_factory(boundary, scripts)
    holder: dict[str, LoopBackend] = {}

    def backend_factory(root: Path) -> LoopBackend:
        backend = LoopBackend.open(root, keychain_backend=keys)
        holder["backend"] = backend
        return backend

    runner = LoopTaskRunner(
        boundary,
        approve_writes=True,
        backend_factory=backend_factory,
        runtime_factory=factory,
    )
    original = runner._review_verdict
    injected = False

    def verdict_with_correction(review_result, **kwargs):
        nonlocal injected
        verdict = original(review_result, **kwargs)
        if not injected:
            injected = True
            backend = holder["backend"]
            backend.accept_input(
                "task-review-verdict-gap",
                input_id="review-verdict-gap",
                kind=InputKind.CORRECTION,
                body="result.txt must contain NEW",
            )
            backend.handle_next_input(
                "task-review-verdict-gap", affects_goal=True, affects_acceptance=True
            )
        return verdict

    runner._review_verdict = verdict_with_correction  # type: ignore[method-assign]
    result = runner.run(
        task_id="task-review-verdict-gap",
        task_kind="code_change",
        goal="Create result.txt containing OLD",
        check_command=(sys.executable, "-c", "from pathlib import Path; assert Path('result.txt').is_file()"),
    )
    assert result["status"] == "succeeded"
    assert result["cycle"] == 2
    assert (boundary.business_workspace / "result.txt").read_text() == "NEW"
    second_main = [client for role, client in clients if role == "main"][1]
    assert "result.txt must contain NEW" in str(second_main.received_messages[0][-1]["content"])


def test_structured_check_progress_requires_stable_ids_and_real_reduction() -> None:
    base = {
        "schema": "SITINA_LOOP_CHECK_PROGRESS_V1",
        "satisfied": ["requirement-a"],
        "remaining": ["requirement-b", "requirement-c"],
    }
    advanced = {
        "schema": "SITINA_LOOP_CHECK_PROGRESS_V1",
        "satisfied": ["requirement-a", "requirement-b"],
        "remaining": ["requirement-c"],
    }
    renamed_noise = {
        "schema": "SITINA_LOOP_CHECK_PROGRESS_V1",
        "satisfied": ["different-a", "different-b"],
        "remaining": ["different-c"],
    }
    assert _structured_progress_advanced(base, advanced) is True
    assert _structured_progress_advanced(base, base) is False
    assert _structured_progress_advanced(base, renamed_noise) is False
    assert _structured_progress_advanced(None, advanced) is False


def test_structured_program_progress_resets_only_the_consecutive_no_progress_count(
    tmp_path: Path,
) -> None:
    boundary = boundary_fixture(tmp_path)
    scripts: list[list[ProviderToolTurn]] = []
    for index, path in enumerate(
        ("requirement-a.done", "requirement-b.done", "noise-1.txt", "noise-2.txt", "noise-3.txt", "noise-4.txt")
    ):
        scripts.append([
            turn("", ProviderToolCall(
                f"progress-write-{index}",
                "sitina_write_file",
                {"path": path, "content": "done"},
            )),
            turn(f"attempt {index + 1}"),
        ])
    runner, _clients, keys = runner_for(boundary, {"main": scripts, "reviewer": []})
    check_script = (
        "import json,os; from pathlib import Path; "
        "ids=['requirement-a','requirement-b','requirement-c']; "
        "satisfied=[item for item in ids if Path(item+'.done').is_file()]; "
        "remaining=[item for item in ids if item not in satisfied]; "
        "Path(os.environ['SITINA_CHECK_OUTPUT'],'progress.json').write_text(json.dumps({"
        "'schema':'SITINA_LOOP_CHECK_PROGRESS_V1','satisfied':satisfied,'remaining':remaining})); "
        "raise SystemExit(1)"
    )
    result = runner.run(
        task_id="task-structured-progress",
        task_kind="code_change",
        goal="Satisfy all three stable requirements",
        check_command=(sys.executable, "-c", check_script),
    )
    assert result["status"] == "stalled"
    assert result["cycle"] == 6
    assert result["settled_attempt_count"] == 4
    with LoopBackend.open(boundary.state_root, keychain_backend=keys) as reopened:
        settlements = reopened.get_task("task-structured-progress").attempt_settlements
        preflight = [item for item in settlements if item["blocker_id"] == "preflight-program-check"]
        assert len(preflight) == 1
        assert preflight[0]["count_effect"] == "COUNT_NEUTRAL"
        business_checks = [
            item for item in settlements if item["blocker_id"].startswith("program-check:")
        ]
        assert [item["relevant_progress"] for item in business_checks] == [
            False,
            True,
            False,
            False,
            False,
            False,
        ]
        assert business_checks[1]["progress_basis"]["satisfied"] == [
            "requirement-a",
            "requirement-b",
        ]
        assert business_checks[-1]["progress_basis"]["satisfied"] == [
            "requirement-a",
            "requirement-b",
        ]


def test_unique_state_authority_rejects_rebinding_during_live_owner_and_after_unknown(
    tmp_path: Path,
) -> None:
    boundary = boundary_fixture(tmp_path)
    boundary.business_workspace.mkdir(parents=True)
    alternate = boundary.state_root.parent / "alternate-authority"
    environment = {"SITINA_HOME": str(boundary.source_root), "SITINA_R4_DEV_ROOT": str(boundary.source_root)}

    with LoopAuthorityLease(boundary.state_root):
        with pytest.raises(Exception, match="unique state authority"):
            DevelopmentBoundary.validate(
                source_root=boundary.source_root,
                interpreter=boundary.source_root / ".venv-r4/bin/python",
                state_root=alternate,
                business_workspace=boundary.business_workspace,
                environment=environment,
            )
    assert not alternate.exists()

    keys = MemoryKeychainBackend()
    with LoopAuthorityLease(boundary.state_root):
        with LoopBackend.open(boundary.state_root, keychain_backend=keys) as backend:
            backend.create_task(
                task_id="task-unknown-owner",
                session_id="session",
                task_kind="code_change",
                goal="write shared.txt",
                required_outcome_ids=("outcome-1",),
                artifact_ref="cas:initial",
                environment_ref="fixture",
                capability_snapshot_id="fixture",
            )
            adapter = LoopOperationAdapter(backend, "task-unknown-owner", boundary.business_workspace)
            with pytest.raises(Exception, match="unknown"):
                adapter.tool_call(
                    "run-unknown",
                    ProviderToolCall("unknown-write", "sitina_write_file", {"path": "shared.txt", "content": "x"}),
                    lambda: (_ for _ in ()).throw(RuntimeError("unknown transport outcome")),
                    permission="write",
                )
            assert backend.operations.unknown_effect_owner is not None

    with pytest.raises(Exception, match="unique state authority"):
        DevelopmentBoundary.validate(
            source_root=boundary.source_root,
            interpreter=boundary.source_root / ".venv-r4/bin/python",
            state_root=alternate,
            business_workspace=boundary.business_workspace,
            environment=environment,
        )
    assert not alternate.exists()
    assert not (boundary.business_workspace / "shared.txt").exists()
