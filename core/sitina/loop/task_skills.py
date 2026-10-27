"""Task-owned access to the same Skill management service used by the web UI."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Mapping

from sitina.execution import ExecutionDenied, execution_authorization
from sitina.extensions.skill_sources import PublicSkillSourceFetcher
from sitina.web.capabilities import SkillsService
from sitina.legacy.fence import authorized_extension_effect


def _user_texts(backend: Any, task: Any) -> list[str]:
    goal = backend.context_memory.read(task.goal_ref)
    texts = [goal["goal"]] if isinstance(goal, Mapping) and isinstance(goal.get("goal"), str) else []
    for item in task.inputs:
        if item.sequence > task.handled_input_seq or item.kind.value not in {"MESSAGE", "CORRECTION", "CLARIFICATION"}:
            continue
        body = backend.context_memory.read(item.body_ref, expected_hash=item.body_hash)
        if (isinstance(body, Mapping) and body.get("task_id") == task.task_id
                and body.get("kind") == item.kind.value and isinstance(body.get("body"), str)):
            texts.append(body["body"])
    return texts


def user_named_source(backend: Any, task: Any, source: str) -> bool:
    """A retrieved page, Skill body, model plan or tool result cannot nominate a source."""
    if not isinstance(source, str) or not source.startswith("https://") or len(source) > 4096:
        return False
    for text in _user_texts(backend, task):
        for match in re.findall(r"https://[^\s<>]+", text):
            if match.strip("\"'()[]{}.,;。；，！!?") == source:
                return True
    return False


def _inspection_allows(backend: Any, task: Any, source: str, selected: str) -> bool:
    for operation in task.operations.values():
        if not operation.result_ref or operation.unknown_effect:
            continue
        document = backend.context_memory.read(str(operation.result_ref))
        if not isinstance(document, Mapping) or document.get("effect_status") != "SUCCEEDED":
            continue
        value = document.get("result")
        if not isinstance(value, Mapping) or value.get("tool") != "sitina_manage_skills":
            continue
        arguments = value.get("arguments")
        inspection = value.get("inspection")
        if (not isinstance(arguments, Mapping) or arguments.get("action") != "inspect"
                or arguments.get("source") != source or not isinstance(inspection, Mapping)):
            continue
        choices = inspection.get("choices")
        if isinstance(choices, list) and any(
                isinstance(choice, Mapping) and choice.get("source") == selected for choice in choices):
            return True
    return False


def resolve_install_selection(backend: Any, task: Any, source: Any, selected: Any) -> tuple[str, str]:
    """Recover only an unambiguous user-authorized, inspected source binding."""
    matches = set()
    for operation in task.operations.values():
        if not operation.result_ref or operation.unknown_effect:
            continue
        document = backend.context_memory.read(str(operation.result_ref))
        if not isinstance(document, Mapping) or document.get('effect_status') != 'SUCCEEDED':
            continue
        value = document.get('result')
        if not isinstance(value, Mapping) or value.get('tool') != 'sitina_manage_skills':
            continue
        arguments, inspection = value.get('arguments'), value.get('inspection')
        if not isinstance(arguments, Mapping) or arguments.get('action') != 'inspect' or not isinstance(inspection, Mapping):
            continue
        original = arguments.get('source')
        choices = inspection.get('choices')
        if (not isinstance(original, str) or not user_named_source(backend, task, original)
                or source is not None and source != original or not isinstance(choices, list)):
            continue
        candidates = [item['source'] for item in choices
                      if isinstance(item, Mapping) and isinstance(item.get('source'), str)]
        for candidate in candidates:
            if selected == candidate or len(candidates) == 1 and selected in {None, original}:
                matches.add((original, candidate))
    if len(matches) != 1:
        raise ExecutionDenied('Install requires one exact choice from an inspected user source; supply source and selected_source to disambiguate.')
    return next(iter(matches))


def _skill_retry_request(service: Any, original: Mapping[str, Any], prior_request_id: Any) -> dict[str, Any]:
    """Create a bounded successor only to an authenticated pre-install failure.

    Repeating the same retry binds the same successor ID, so the authority's
    existing dispatch barrier still handles concurrency and lost responses.
    This does not retry a started, successful, or preparation-stage operation.
    """
    base = str(original["request_id"])
    ids = (base, base + "-retry-2", base + "-retry-3")
    if not isinstance(prior_request_id, str) or prior_request_id not in ids:
        raise ExecutionDenied("Skill retry must reference this source's exact prior management_request_id")
    ordinal = ids.index(prior_request_id)
    key = hashlib.sha256(prior_request_id.encode("utf-8")).hexdigest()
    started = service.authority._existing_request("skill-management-start-" + key)
    finished = service.authority._existing_request("skill-management-finish-" + key)
    expected = {**dict(original), "request_id": prior_request_id}
    if (started is None or finished is None
            or started.payload.get("management_request") != expected
            or finished.payload.get("management_request") != expected):
        raise ExecutionDenied("Skill retry not dispatched: original request is unresolved or its source binding differs; use status")
    result = finished.payload.get("result")
    if (not isinstance(result, Mapping) or result.get("request_id") != prior_request_id
            or result.get("state") != "FAILED"
            or "management_task_id" not in result or result["management_task_id"] is not None):
        raise ExecutionDenied("Skill retry not dispatched: only a confirmed failure before installation preparation is retryable; preserve successful or unknown operations")
    if ordinal == len(ids) - 1:
        raise ExecutionDenied("Skill installation reached three attempts; report the blocker and preserve results instead of repeating the action")
    return {**dict(original), "request_id": ids[ordinal + 1]}


def _skill_management_recovery(result: Mapping[str, Any], prefix: str) -> dict[str, Any]:
    request_id = result.get("request_id")
    match = re.fullmatch(re.escape(prefix) + r"[0-9a-f]{64}(?:-retry-(2|3))?", request_id) if isinstance(request_id, str) else None
    attempt = int(match.group(1) or "1") if match else None
    safe = (result.get("state") == "FAILED" and "management_task_id" in result
            and result["management_task_id"] is None and attempt is not None and attempt < 3)
    return {
        "attempt": attempt, "maximum_attempts": 3, "can_retry": safe,
        "original_result_replayed": result.get("replayed") is True,
        "next_action": "retry" if safe else "status" if result.get("state") == "UNKNOWN" else "report_result",
        "retry_requires_request_id": request_id if safe else None,
        "instruction": ("原失败已确定且未进入安装准备；确需再次尝试时使用 retry 和本回执的 management_request_id。重复 install 只返回原结果。"
                        if safe else "保留原结果；成功或结果未知的操作不得重新安装。达到三次或已进入安装准备的失败，应报告具体阻塞。"),
    }


def manage_task_skills(runtime: Any, adapter: Any, arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Called inside the existing native operation/replay barrier."""
    action = arguments.get("action")
    if action not in {"inspect", "install", "retry", "status"}:
        raise ExecutionDenied("unknown Skill management action")
    if adapter.execution_owner or not adapter.mutation_allowed or not runtime.approve_writes:
        raise ExecutionDenied("Skill installation requires the user's writable main task")
    manager = getattr(adapter, "_task_skill_manager", None)
    if manager is None:
        raise ExecutionDenied("task Skills are not bound to the authenticated global store")
    task = adapter.backend.get_task(adapter.task_id)
    source = arguments.get("source")
    selected = arguments.get('selected_source')
    if action in {'install', 'retry'}:
        source, selected = resolve_install_selection(adapter.backend, task, source, selected)
    if action != "status":
        if not user_named_source(adapter.backend, task, source):
            raise ExecutionDenied("Skill source must be named in an authenticated user request")
        authorization = execution_authorization(adapter.backend, adapter.task_id)
        if authorization.get("public_web_read") is not True:
            raise ExecutionDenied("public Skill import requires this task's anonymous public-read permission")
    fetcher = PublicSkillSourceFetcher(runtime.boundary.state_root / "checks" / "skill-sources")
    factory = getattr(runtime, "skill_management_service_factory", None)
    service = factory() if callable(factory) else SkillsService(manager, public_source_fetcher=fetcher)
    if callable(factory) and Path(service.manager.root).resolve() != Path(manager.root).resolve():
        raise ExecutionDenied("Skill management service belongs to another global store")
    prefix = "task-skill-" + hashlib.sha256(adapter.task_id.encode()).hexdigest()[:20] + "-"
    if action == "status":
        request_id = arguments.get("request_id")
        if not isinstance(request_id, str) or not request_id.startswith(prefix):
            raise ExecutionDenied("Skill status request must belong to this task")
        operation_key = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        finished = service.authority._existing_request("skill-management-finish-" + operation_key)
        started = service.authority._existing_request("skill-management-start-" + operation_key)
        if finished is not None:
            result = finished.payload.get("result")
            if not isinstance(result, Mapping) or result.get("request_id") != request_id:
                raise ExecutionDenied("original Skill result has an invalid request binding")
        elif started is not None:
            result = {"request_id": request_id, "state": "UNKNOWN",
                      "message": "原安装尚无终态，请保留原请求，勿重新安装。"}
        else:
            raise ExecutionDenied("original Skill operation is not available; do not reinstall it")
        state = ("SUCCEEDED" if result.get("state") == "ACCEPTED" and result.get("installed") is True else result["state"])
        return {"state": state, "management": dict(result),
                "management_request_id": request_id,
                "recovery": _skill_management_recovery(result, prefix)}
    if action == "inspect":
        request_id = prefix + hashlib.sha256(("inspect:" + source).encode()).hexdigest()[:32]
        try:
            with authorized_extension_effect(permission="install_network", approval_granted=True,
                                             purpose="task-authorized-public-skill-inspection"):
                inspection = service.inspect_source({"source": source, "request_id": request_id})
        except Exception as error:
            # This operation only reads a public source into disposable scratch;
            # it cannot have changed the global installed Skill selection.
            return {"state": "FAILED", "code": "SKILL_SOURCE_INSPECTION_FAILED",
                    "message": str(error), "error_type": type(error).__name__, "installed": False}
        return {"state": "SUCCEEDED", "inspection": inspection, 'source_binding': {'source': source}}
    if not isinstance(selected, str) or not _inspection_allows(adapter.backend, task, source, selected):
        raise ExecutionDenied("inspect the user source first and select an exact returned choice")
    enabled = arguments.get("enable", True)
    if type(enabled) is not bool:
        raise ExecutionDenied("Skill enable must be boolean")
    identity = repr((source, selected, enabled))
    request_id = prefix + hashlib.sha256(identity.encode()).hexdigest()
    request = {"action": "install_public", "source": selected,
               "request_id": request_id, "enable": enabled}
    if action == "retry":
        request = _skill_retry_request(service, request, arguments.get("request_id"))
        request_id = request["request_id"]
    with authorized_extension_effect(permission="install_network", approval_granted=True,
                                     purpose="task-authorized-public-skill-install"):
        result = service.mutate(request, user_initiated=True)
    state = ('SUCCEEDED' if result.get('state') == 'ACCEPTED' and result.get('installed') is True
             else result['state'])
    return {"state": state, "management": result,
            'source_binding': {'source': source, 'selected_source': selected},
            "management_request_id": request_id, "task_versions": "unchanged",
            "recovery": _skill_management_recovery(result, prefix),
            "message": "安装与启用结果见 management；已有任务保留固定版本，新任务使用新版本。"}
