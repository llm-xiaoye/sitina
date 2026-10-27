from __future__ import annotations

import base64
import fcntl
import hashlib
import logging
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from sitina.conversation.context import ConversationContext, ConversationContextSnapshot
from sitina.conversation.models import ChatMode, ConversationTurn
from sitina.conversation.router import ConversationRouter
from sitina.execution import TASK_EXECUTION_CONTRACT
from sitina.loop.control import (
    LoopAuthorityLease, LoopAuthorityError, control_delivery_failure,
    authority_socket_path, input_receipt, send_control_input, send_control_request,
)
from sitina.loop.development import default_runtime_locations, validate_runtime_boundary
from sitina.loop.model import InputKind, REVIEW_REQUIRED_TASK_KINDS, TaskConflict, PersistenceFenced
from sitina.loop.model_selection import ModelSelectionStore
from sitina.loop.recovery import RecoveryCoordinator
from sitina.loop.status_reader import (
    _read_json as _read_native_document, read_authenticated_journal, read_task_status,
)
from sitina.loop.storage import LoopRuntimeContext
from sitina.security.macos_keychain import MacOSKeychainProvider
from sitina.security.redaction import redact_text
from .activity import activity_page, activity_summary, operation_activities
from .deletions import DeletionQueue

TERMINAL = {"SUCCEEDED", "FAILED", "CANCELLED"}
ANIMATING = {"RUNNABLE", "WAITING_OPERATION", "WAITING_CHILD", "PAUSING", "CANCELLING"}
SID = re.compile(r"[0-9a-f]{32}\Z")
RID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
MAX_UPLOAD = 8 * 1024 * 1024
MAX_FILE_HISTORY_CACHE_ITEMS = 64
MAX_FILE_HISTORY_CACHE_BYTES = 4 * 1024 * 1024


def _logical_rounds(totals):
    values = totals.get("values") if isinstance(totals, dict) else None
    value = values.get("logical_turn_count") if isinstance(values, dict) else None
    return value if type(value) is int and value >= 0 else None


def _verification_activity(task):
    """Project real completion-check identities separately from reviewer Agents."""
    telemetry = task.get("agent_telemetry")
    if not isinstance(telemetry, dict):
        return {"completion_checks": None, "active_role": None}
    records = list(telemetry.get("unattributed_operations") or [])
    for group in telemetry.get("agents") or []:
        records.extend(group.get("operations") or [])
    identities, active_roles = set(), set()
    active_ids = set(task.get("active_operation_ids") or [])
    for record in records:
        actor = record.get("actor") or {}
        role, identity = actor.get("role"), actor.get("instance_id")
        if role == "goal_completion" and identity:
            identities.add(identity)
        if record.get("operation_id") in active_ids:
            active_roles.add(role)
    active_role = None
    if task.get("status") not in TERMINAL and task.get("control_intent") == "RUN":
        active_role = next((role for role in ("reviewer", "goal_completion", "main", "goal_interpretation")
                            if role in active_roles), None)
    return {"completion_checks": len(identities), "active_role": active_role}


def _verification_history(task, events, read_document):
    """Use committed attempt order, not polling frames or provider-call counts."""
    telemetry = task.get("agent_telemetry") or {}
    records = list(telemetry.get("unattributed_operations") or [])
    for group in telemetry.get("agents") or []:
        records.extend(group.get("operations") or [])
    roles = {}
    active_attempts = set()
    for record in records:
        actor = record.get("actor") or {}
        identity, role = actor.get("instance_id"), actor.get("role")
        if identity and role in {"reviewer", "goal_completion"}:
            roles[identity] = role
            if record.get("operation_id") in (task.get("active_operation_ids") or []):
                active_attempts.add(identity)
    goal = task.get("goal_summary") or {}
    checks = list(dict.fromkeys(
        text for text in [
            *(goal.get("acceptance_conditions") or []), *(goal.get("constraints") or []),
            *((goal.get("intent") or {}).get("negative_constraints") or []),
        ] if isinstance(text, str) and text.strip()
    ))
    if isinstance(goal.get("goal"), str) and goal["goal"].strip():
        checks.append("完整满足本次请求：" + goal["goal"])
    rows, by_id, settlements = [], {}, {}
    notice_at = None
    for event in events:
        if event.stream_id != "loop-task/" + task["task_id"] or event.stream_version > task["task_revision"]:
            continue
        payload = event.payload
        if event.event_type == "loop.attempt-planned":
            plan = read_document(payload, "plan_ref", "plan_hash")
            identity = plan["attempt_id"]
            role = roles.get(identity)
            if str(plan.get("blocker_id", "")).startswith("goal-completion:"):
                role = "goal_completion"
            if role not in {"reviewer", "goal_completion"} or identity in by_id:
                continue
            prior = by_id.get(plan.get("prior_attempt_id"))
            prior_outcome = settlements.get(plan.get("prior_attempt_id"), "")
            repair = bool(prior and prior_outcome.startswith(("Invalid completion decision:", "Invalid review")))
            current = all(plan.get(key) == task.get(key) for key in ("goal_version", "acceptance_version"))
            row = {
                "id": identity, "role": role, "ordinal": len(rows) + 1, "at": event.occurred_at,
                "kind": "repair" if repair else "assessment",
                "checks": checks if current else ["核对当时版本的任务要求与成果"],
                "status": "RUNNING" if identity in active_attempts and task.get("control_intent") == "RUN"
                else "RECORDED",
            }
            by_id[identity] = row
            rows.append(row)
        elif event.event_type == "loop.attempt-settled":
            document = read_document(payload, "settlement_ref", "settlement_hash")
            identity = document["attempt_id"]
            outcome = str(document.get("outcome") or "")
            settlements[identity] = outcome
            if identity in by_id:
                by_id[identity]["status"] = (
                    "CORRECTION_NEEDED" if outcome.startswith(("Invalid completion decision:", "Invalid review"))
                    else "RECORDED"
                )
        elif event.event_type == "loop.task-waiting":
            notice_at = event.occurred_at
    return {"history": rows, "notice_at": notice_at}


def _task_notice(task):
    """A runtime explanation, never a fabricated model answer or success."""
    waiting = task.get("waiting_reason") or {}
    reason = str(waiting.get("reason") or waiting.get("message") or "")
    status = task.get("status")
    if status not in {"STALLED", "FAILED", "CONTEXT_BLOCKED", "RECOVERY_BLOCKED", "WAITING_INPUT", "PAUSED"}:
        return None
    resolution = waiting.get("assessment_resolution")
    if resolution is not None:
        from ..loop.assessment_recovery import validate_assessment_stop_resolution
        try:
            resolution = validate_assessment_stop_resolution(resolution, status=status)
        except ValueError:
            pass  # Legacy or damaged metadata must not override the actual task state.
        else:
            detail = "\n原始原因：" + redact_text(reason or "未提供具体回执")[:1200]
            if resolution["cause"] == "capability":
                # Preserve the full authenticated finding in waiting_reason;
                # the conversational notice should not dump internal IDs/JSON.
                try:
                    document = json.loads(reason)
                except (TypeError, ValueError):
                    document = None
                findings = document.get("unmet_requirements") if isinstance(document, dict) else None
                summaries = []
                if isinstance(findings, list):
                    for finding in findings:
                        if (isinstance(finding, dict)
                                and finding.get("finding_code") == "CAPABILITY_UNAVAILABLE"
                                and finding.get("disposition") == "OPEN"
                                and isinstance(finding.get("summary"), str)
                                and finding["summary"].strip()):
                            summaries.append(redact_text(finding["summary"].strip()))
                detail = ("\n具体原因：" + "；".join(summaries)[:700] if summaries else "")
                detail += "\n完整执行回执和核验记录已保留，可在操作记录中查看。"
            return (resolution["summary"] + " 已有文件和操作记录已保留。\n"
                    + resolution["next_action"]
                    + "\n你可以继续询问当前进展或补充要求；只有确实缺少你的决定或材料时，才会提出具体问题。"
                    + detail)
    if waiting.get("blocker_id") in {"review-protocol-repair:outcome-1", "review-independent-recheck:outcome-1"}:
        if reason.startswith("复核回复未通过"):
            return redact_text(reason)[:1800]
        return ("成果已经保留，但复核回复的证据引用或格式校验没有通过，暂时不能确认任务完成。"
                "这是核验流程问题，不是在等待你补交材料。请保留现有文件，先定位或修复下面的具体原因，"
                "再继续核验；不要重复制作成果。原始原因：" + redact_text(reason)[:1200])
    if status == "WAITING_INPUT" and str(waiting.get("blocker_id") or "").startswith("clarification:"):
        return ("需要你补充一项信息：" + redact_text(reason)[:1200]
                + "\n直接在输入框回答即可，我会根据你的回答接着执行。")
    if "Goal completion decision is invalid" in reason:
        detail = "核验答复未完整覆盖要求" if "PASS must cover every current acceptance condition" in reason else "未取得有效的核验结论"
        return f"这次回答的完成核验没有通过：{detail}，自动修正后仍未解决。已有操作和记录已保留，暂时不能确认任务完成。"
    if "review" in reason.lower() and ("invalid" in reason.lower() or "protocol" in reason.lower()):
        return "这次评审没有返回有效结论，自动修正后仍未解决。已有成果和记录已保留，暂时不能确认评审通过。"
    if status == "PAUSED":
        return None
    if status == "WAITING_INPUT":
        return None  # Keep the real clarification question and recovery-specific explanation.
    if status == "RECOVERY_BLOCKED":
        return "这次任务暂时无法恢复，当前版本与已保存状态的衔接检查没有通过。原任务和记录已保留，需要修复后再继续。"
    if status == "CONTEXT_BLOCKED":
        return "上下文整理没有完成，所以任务暂时停住。原因：" + redact_text(reason or "系统未返回具体原因")[:700] + "。已有成果保留；请先核对这条错误，修复后点击“继续”，不用重做已完成的文件。"
    if status in {"STALLED", "FAILED"}:
        if "read-only global extension authority" in reason:
            return ("任务停在扩展加载步骤：Sitina 的只读加载流程误调用了扩展管理接口。"
                    "这是程序内部错误，不是你没有授权。已生成的网页和操作记录仍保留，但任务尚未完成验收。"
                    "请先修复或更新 Sitina，再点击“继续”；反复发送同一条消息不会修好这个问题。")
        if "publication snapshot" in reason or "candidate changed after preparation" in reason:
            return ("任务停在插件完整性检查：已安装扩展的文件与启用时不一致，当前不能继续调用。"
                    "已有成果和记录保留。请修复或重新安装受影响的扩展，再点击“继续”。具体信息："
                    + redact_text(reason)[:700])
        return ("任务暂时停住。原因：" + redact_text(reason or "执行器没有返回具体错误")[:700]
                + "。已完成的文件和操作记录保留；请展开“命令与终端”核对失败步骤。"
                "修正条件后点击“继续”，或直接补充需要调整的要求；不要重复执行结果尚未确认的操作。")
    return None


def _task_context_usage(task):
    telemetry = task.get("agent_telemetry") or {}
    records = list(telemetry.get("unattributed_operations") or [])
    for group in telemetry.get("agents") or []:
        records.extend(group.get("operations") or [])
    contexts = [record["context_usage"] for record in records
                if isinstance(record.get("context_usage"), dict)
                and (record.get("actor") or {}).get("role") == "main"]
    return max(contexts, key=lambda item: str(item.get("observed_at") or "")) if contexts else None


def _agent_activity(task):
    """Use authenticated native telemetry; retries are requests, not new turns."""
    telemetry = task.get("agent_telemetry") if isinstance(task, dict) else None
    if not isinstance(telemetry, dict):
        return None, {}, []
    groups = telemetry.get("agents")
    if not isinstance(groups, list):
        return _logical_rounds(telemetry.get("totals")), {}, []
    unassigned = telemetry.get("unattributed_operations", [])
    # Native tool receipts can lack a provider call ID while their committed
    # intent still identifies the actor. Use that actor for this UI summary;
    # do not change provider-request attribution or count the receipt twice.
    groups = [{**group, "operations": list(group["operations"]) if isinstance(group.get("operations"), list) else []}
              for group in groups if isinstance(group, dict)]
    by_owner = {group.get("delegation_id") or group.get("agent_id"): group for group in groups}
    remaining = []
    for record in unassigned if isinstance(unassigned, list) else []:
        actor = record.get("actor") if isinstance(record, dict) else None
        owner = None
        if isinstance(actor, dict):
            if actor.get("role") in {"main", "goal_interpretation", "goal_completion", "reviewer"}:
                owner = task.get("task_id")
            elif actor.get("role") == "child":
                owner = actor.get("execution_owner") or actor.get("instance_id")
        group = by_owner.get(owner)
        if group is not None and isinstance(record, dict) and record.get("kind") == "tool":
            if not any(item.get("operation_id") == record.get("operation_id") for item in group["operations"]):
                group["operations"].append(record)
        else:
            remaining.append(record)
    unassigned = remaining

    def pending(record):
        return isinstance(record, dict) and record.get("kind") == "unknown" and record.get("result_status") == "INTENT_RECORDED"

    def known_zero_rounds(record):
        metrics = record.get("metrics") if isinstance(record, dict) else None
        return (isinstance(record, dict) and record.get("kind") == "unknown"
                and isinstance(metrics, dict) and type(metrics.get("logical_turn_count")) is int
                and metrics["logical_turn_count"] == 0)

    def completed_rounds(records):
        counts = []
        for record in records:
            if isinstance(record, dict) and record.get("kind") == "provider":
                metrics = record.get("metrics")
                counts.append(metrics.get("logical_turn_count") if isinstance(metrics, dict) else None)
        return sum(counts) if all(type(count) is int and count >= 0 for count in counts) else None

    all_records = list(unassigned) if isinstance(unassigned, list) else []
    for group in groups:
        if isinstance(group, dict) and isinstance(group.get("operations"), list):
            all_records.extend(group["operations"])
    uncertain = [record for record in all_records
                 if not isinstance(record, dict) or (
                     record.get("kind") not in {"provider", "tool"} and not known_zero_rounds(record))]
    only_pending = isinstance(unassigned, list) and bool(uncertain) and all(pending(record) for record in uncertain)
    total_rounds = _logical_rounds(telemetry.get("totals"))
    if total_rounds is None and only_pending:
        total_rounds = completed_rounds(all_records)
    skill_coverage = isinstance(unassigned, list) and all(
        pending(item) or (isinstance(item, dict) and item.get("skill_usage") == []) for item in unassigned)
    activity, reviewers = {}, set()
    for group in groups:
        if not isinstance(group, dict):
            continue
        base = group.get("delegation_id") or group.get("agent_id")
        records = group.get("operations")
        if not isinstance(base, str) or not base or not isinstance(records, list):
            continue
        expected = _logical_rounds(group.get("totals"))
        if expected is None and only_pending:
            expected = completed_rounds(records)
        parts = {base: {"rounds": 0, "skills": {}, "skills_known": skill_coverage}}
        rounds_known = expected is not None
        skills_partition_known = skill_coverage
        for record in records:
            if pending(record) or known_zero_rounds(record):
                continue
            if not isinstance(record, dict):
                rounds_known = False
                skills_partition_known = False
                for part in parts.values():
                    part["skills_known"] = False
                continue
            actor = record.get("actor")
            key = base
            if not isinstance(actor, dict):
                rounds_known = False
                skills_partition_known = False
                for part in parts.values():
                    part["skills_known"] = False
            elif actor.get("role") == "reviewer":
                identity = actor.get("instance_id")
                if not isinstance(identity, str) or not identity:
                    rounds_known = False
                    skills_partition_known = False
                    for part in parts.values():
                        part["skills_known"] = False
                else:
                    key = identity
                    reviewers.add(key)
            part = parts.setdefault(key, {"rounds": 0, "skills": {}, "skills_known": skills_partition_known})
            kind = record.get("kind")
            if kind == "provider":
                metrics = record.get("metrics")
                count = metrics.get("logical_turn_count") if isinstance(metrics, dict) else None
                if type(count) is int and count >= 0:
                    part["rounds"] += count
                else:
                    rounds_known = False
            elif kind == "tool":
                usage = record.get("skill_usage")
                if not isinstance(usage, list):
                    part["skills_known"] = False
                    continue
                for item in usage:
                    if not isinstance(item, dict) or not isinstance(item.get("name"), str) or item.get("status") not in {"used", "failed"}:
                        part["skills_known"] = False
                        continue
                    skill = part["skills"].setdefault(item["name"], {"name": item["name"], "uses": 0, "loads": 0, "resource_reads": 0, "failures": 0, "resources": set()})
                    skill["uses" if item["status"] == "used" else "failures"] += 1
                    if item["status"] == "used":
                        skill["loads" if item.get("action") == "load" else "resource_reads"] += 1
                    if isinstance(item.get("resource"), str):
                        skill["resources"].add(item["resource"])
            else:
                skills_partition_known = False
                for item in parts.values():
                    item["skills_known"] = False
        rounds_known = rounds_known and sum(item["rounds"] for item in parts.values()) == expected
        for key, part in parts.items():
            items = [{**item, "resources": sorted(item["resources"])} for _, item in sorted(part["skills"].items())]
            activity[key] = {
                "interaction_rounds": part["rounds"] if rounds_known else None,
                "skills": {"count": sum(item["uses"] > 0 for item in items),
                           "invocations": sum(item["uses"] for item in items),
                           "failed_invocations": sum(item["failures"] for item in items),
                           "items": items} if part["skills_known"] else None,
            }
    return total_rounds, activity, sorted(reviewers)


def _agent_data_flow(task):
    """Logical call/return indicators from recorded ownership, never packet counts."""
    telemetry = task.get("agent_telemetry")
    if not isinstance(telemetry, dict) or not isinstance(telemetry.get("agents"), list):
        return {}
    active = task.get("active_operation_ids")
    if not isinstance(active, list) or not all(isinstance(item, str) for item in active):
        return {}
    active = set(active)
    children = task.get("child_delegations")
    children = children if isinstance(children, dict) else {}
    main_id = task.get("task_id")
    parts = {}

    def accept(record, owner):
        if not isinstance(record, dict) or not isinstance(owner, str) or not owner:
            return
        operation_id = record.get("operation_id")
        if not isinstance(operation_id, str) or not operation_id:
            return
        actor = record.get("actor")
        if not isinstance(actor, dict) or actor.get("role") not in {"main", "child", "reviewer"}:
            return
        if actor.get("role") == "reviewer":
            owner = actor.get("instance_id")
            if not isinstance(owner, str) or not owner:
                return
        part = parts.setdefault(owner, {"active": set(), "returned": set()})
        if operation_id in active and record.get("result_status") == "INTENT_RECORDED":
            part["active"].add(operation_id)
        elif (record.get("kind") in {"provider", "tool"}
              and record.get("result_status") in {"SUCCEEDED", "FAILED", "CANCELLED"}
              and isinstance(record.get("result_ref"), str) and record["result_ref"]):
            part["returned"].add(operation_id + ":" + record["result_ref"])

    for group in telemetry["agents"]:
        if not isinstance(group, dict) or not isinstance(group.get("operations"), list):
            continue
        owner = group.get("delegation_id") or group.get("agent_id")
        for record in group["operations"]:
            accept(record, owner)
    unassigned = telemetry.get("unattributed_operations")
    if isinstance(unassigned, list):
        for record in unassigned:
            if not isinstance(record, dict) or not isinstance(record.get("actor"), dict):
                continue
            actor = record["actor"]
            if actor.get("role") == "main":
                owner = main_id
            elif actor.get("role") == "reviewer":
                owner = actor.get("instance_id")
            elif (actor.get("role") == "child" and isinstance(actor.get("instance_id"), str)
                  and actor["instance_id"] in children):
                owner = actor["instance_id"]
            else:
                continue
            # Pending intents have no result identity yet; the committed actor
            # and current active-operation set must both establish ownership.
            if record.get("result_status") == "INTENT_RECORDED":
                accept(record, owner)
    flows = {}
    for owner, part in parts.items():
        phase = "request" if part["active"] else "returned"
        observations = sorted(part["active"] or part["returned"])
        if observations:
            digest = hashlib.sha256(json.dumps(observations, separators=(",", ":")).encode()).hexdigest()
            flows[owner] = {"phase": phase, "event_key": phase + ":" + digest,
                            "source": "authenticated_operation_telemetry"}
    return flows


class WebError(RuntimeError):
    def __init__(self, message: str, *, code: str = "conflict", status: int = 409):
        super().__init__(message)
        self.code, self.status = code, status


def _physical(path: Path, *, directory: bool = True) -> Path:
    """Check lexical ancestors; never follow a user-created link into a tree."""
    for parent in (path, *path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise WebError("会话路径包含符号链接，已停止操作。", code="unsafe_path")
    if directory and path.exists() and not path.is_dir():
        raise WebError("会话目录类型异常，已停止操作。", code="unsafe_path")
    return path


def _json(path: Path) -> dict[str, Any]:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022 or info.st_size > 16 * 1024 * 1024):
        raise WebError("会话记录的类型、权限或大小异常。", code="unsafe_metadata")
    with path.open("rb") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise WebError("会话记录格式异常。", code="unsafe_metadata")
    return value


def _write(path: Path, value: Any) -> None:
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    temp = path.parent / (".web-write-" + secrets.token_hex(12))
    descriptor = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temp.exists():
            temp.unlink()


def _native_factory(args):
    from sitina.cli import build_native_loop_host
    return build_native_loop_host(args)


class WebSessions:
    """A directory registry of independent native Loop conversations.

    No shared CLI Journal is imported or split. HTTP reads never launch a
    Host, resume work, submit a task, or resolve a Provider credential.
    """

    def __init__(self, source: Path, runtime: Path, *,
                 host_factory: Callable[..., Any] = _native_factory,
                 keychain_backend: Any | None = None, skills_service: Any | None = None,
                 skills_root: Path | None = None):
        self.source = _physical(source.absolute()).resolve(strict=True)
        self.runtime = _physical(runtime.absolute())
        self.root = _physical(self.runtime / "workspaces/web")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._hosts: dict[str, Any] = {}
        self._dispatch_locks: dict[str, threading.RLock] = {}
        self._inflight_dispatches: set[tuple[str, str]] = set()
        self._response_history: dict[tuple[str, str], tuple[tuple[str, int], list[dict[str, Any]]]] = {}
        self._verification_history_cache = {}
        self._activity_history_cache = {}
        self._file_history = OrderedDict()
        self._file_history_bytes = 0
        self._locks: dict[str, threading.RLock] = {}
        self._guard = threading.RLock()
        self.factory = host_factory
        self.keychain_backend = keychain_backend
        self._skills_service = skills_service
        self._skills_root = Path(skills_root).expanduser().resolve(strict=False) if skills_root is not None else None
        self._skills_backend = self._skills_lease = None
        self._skills_mutations = 0
        self.router = ConversationRouter.load(self.source)
        self.conversation_context = ConversationContext.load(self.source)
        from sitina.user_memory import UserMemoryStore
        self.user_memory = UserMemoryStore(self.runtime / "user-memory.json")
        self._closed = False
        self._lease = os.open(self.root / ".server.lock",
                              os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self._lease)
            raise WebError("此会话库已经由另一个网页服务使用。", code="registry_busy")
        self.deletion_queue = DeletionQueue(self.runtime / "web-deletions.json", self.delete,
                                            self._deletion_title, self._deletion_observation)

    def _deletion_observation(self, sid):
        """Read the final filesystem state; never resume or repeat deletion."""
        if not isinstance(sid, str) or not SID.fullmatch(sid):
            return {"confirmation":"UNKNOWN", "reason_code":"invalid_session_id"}
        with self._lock(sid):
            _physical(self.root)
            path = self.root / sid
            try:
                info = path.lstat()
            except FileNotFoundError:
                tombstone = self.root / (".deleted-" + sid)
                try:
                    marker = tombstone.lstat()
                except FileNotFoundError:
                    return {"confirmation":"UNKNOWN", "reason_code":"missing_deletion_receipt"}
                valid = stat.S_ISREG(marker.st_mode) and marker.st_size == 0 and marker.st_uid == os.getuid()
                return {"confirmation":"REMOVED" if valid else "UNKNOWN",
                        "reason_code":"directory_removed" if valid else "unsafe_tombstone"}
            retained = stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            return {"confirmation":"RETAINED" if retained else "UNKNOWN",
                    "reason_code":"directory_present" if retained else "unsafe_session_path"}

    def _deletion_title(self, sid):
        if self._deletion_observation(sid)["confirmation"] == "REMOVED":
            return "已删除会话"
        return self._meta(sid)["title"]

    def start_deletion(self, body):
        if not isinstance(body, dict) or set(body) != {"request_id", "session_ids", "confirmation"} or body["confirmation"] != "permanent":
            raise WebError("请明确确认永久删除选中的会话。", status=400, code="confirmation_required")
        try:
            return self.deletion_queue.create(body["request_id"], body["session_ids"])
        except ValueError as error:
            raise WebError(str(error), status=409, code="deletion_conflict") from error

    def memory_view(self, sid):
        project = self._meta(sid).get("memory_project", "") if sid else ""
        return {"project": project, "items": self.user_memory.list(project)}

    def memory_action(self, body):
        sid = body.get("session_id")
        action = body.get("action")
        try:
            if action == "set_project":
                with self._lock(sid):
                    meta = self._mutable(sid)
                    meta["memory_project"] = self.user_memory.project(body.get("project", ""))
                    self._save(sid, meta)
                return self.memory_view(sid)
            project = self._meta(sid).get("memory_project", "") if sid else ""
            item_id = body.get("id")
            if item_id and item_id not in {item["id"] for item in self.user_memory.list(project)}:
                raise ValueError("当前项目中没有这条记忆。")
            if action == "save":
                return {"item": self.user_memory.put(kind=body.get("kind"), content=body.get("content"),
                    project=project, status="active", item_id=item_id,
                    source={"type":"user_edit", "session_id":sid})}
            if action in {"approve", "delete"}:
                return self.user_memory.control(item_id, action)
            raise ValueError("记忆操作无效。")
        except ValueError as error:
            raise WebError(str(error), status=400, code="invalid_memory") from error

    def control_deletion(self, job_id, body):
        if not isinstance(body, dict) or set(body) != {"action"}:
            raise WebError("删除队列操作无效。", status=400, code="invalid_deletion")
        try:
            return self.deletion_queue.control(job_id, body["action"])
        except ValueError as error:
            raise WebError(str(error), status=409, code="deletion_conflict") from error
    @classmethod
    def current(cls):
        state, workspace = default_runtime_locations()
        boundary = validate_runtime_boundary(state_root=state, business_workspace=workspace)
        return cls(boundary.source_root, boundary.runtime_root)

    def _lock(self, sid: str):
        if not isinstance(sid, str) or not SID.fullmatch(sid):
            raise WebError("无效会话 ID。", status=404, code="not_found")
        with self._guard:
            return self._locks.setdefault(sid, threading.RLock())

    def _command_lock(self, sid: str):
        self._lock(sid)  # Validate the session identity before indexing locks.
        with self._guard:
            return self._dispatch_locks.setdefault(sid, threading.RLock())

    def _pending_submission_task_ids(self, sid, meta):
        return {action["task_id"] for rid, action in meta["actions"].items()
                if (sid, rid) in self._inflight_dispatches
                and action["kind"] == "submit" and action["state"] == "PENDING"}

    def directory(self, sid: str) -> Path:
        self._lock(sid)
        path = _physical(self.root / sid)
        if not path.is_dir():
            raise WebError("会话不存在或已删除。", status=404, code="not_found")
        expected = {"schema": "SITINA_WEB_SESSION_OWNER_V1", "session_id": sid,
                    "source_root": str(self.source), "state_root": str(path / "state"),
                    "workspace": str(path / "workspace")}
        if _json(path / ".web-session-owner.json") != expected:
            raise WebError("会话所属目录无法核实，已停止操作。", code="owner_mismatch")
        return path

    def _meta(self, sid: str) -> dict[str, Any]:
        path = self.directory(sid)
        value = _json(path / "session.json")
        if (value.get("schema") != "SITINA_WEB_CONVERSATION_V1"
                or value.get("id") != sid or not isinstance(value.get("messages"), list)
                or not isinstance(value.get("actions"), dict)):
            raise WebError("会话记录无法核实。", code="unsafe_metadata")
        return value

    def create(self, request_id: str) -> dict[str, Any]:
        self._request_id(request_id)
        sid = hashlib.sha256(("sitina-web-create:" + request_id).encode()).hexdigest()[:32]
        with self._lock(sid):
            if self._closed:
                raise WebError("服务正在停止。", code="server_stopping")
            # A replay of the same explicit create only returns its directory.
            if (self.root / sid).exists():
                return self.summary(self._meta(sid))
            deleted = self.root / (".deleted-" + sid)
            if deleted.exists():
                raise WebError("这个新建请求对应的会话已删除，请使用新的新建操作。", code="deleted_request")
            path = self.root / sid
            path.mkdir(mode=0o700)
            (path / "workspace/uploads").mkdir(parents=True, mode=0o700)
            _write(path / ".web-session-owner.json", {
                "schema": "SITINA_WEB_SESSION_OWNER_V1", "session_id": sid,
                "source_root": str(self.source), "state_root": str(path / "state"),
                "workspace": str(path / "workspace"),
            })
            meta = {"schema": "SITINA_WEB_CONVERSATION_V1", "id": sid, "title": "新会话",
                    "created_at": time.time(), "updated_at": time.time(), "revision": 1,
                    "messages": [], "actions": {}, "uploads": [], "deleting": False,
                    "delete_error": None}
            _write(path / "session.json", meta)
            return self.summary(meta)

    @staticmethod
    def summary(meta: dict[str, Any]) -> dict[str, Any]:
        return {key: meta[key] for key in
                ("id", "title", "created_at", "updated_at", "revision", "deleting", "delete_error")}

    def list(self) -> list[dict[str, Any]]:
        values = []
        for path in self.root.iterdir():
            if SID.fullmatch(path.name):
                with self._lock(path.name):
                    try:
                        values.append(self.summary(self._meta(path.name)))
                    except (WebError, OSError, ValueError, KeyError) as error:
                        # A partial final unlink must remain visible. It is
                        # never silently treated as a successful deletion.
                        values.append({"id": path.name, "title": "会话记录待核对",
                            "created_at": 0, "updated_at": 0, "revision": 0,
                            "deleting": True, "delete_error": redact_text(str(error))})
        return sorted(values, key=lambda item: item["updated_at"], reverse=True)

    @staticmethod
    def _request_id(value):
        if not isinstance(value, str) or not RID.fullmatch(value):
            raise WebError("缺少有效的操作身份。", status=400, code="invalid_request_id")

    def _mutable(self, sid: str):
        meta = self._meta(sid)
        if self._closed or meta["deleting"]:
            raise WebError("会话已停止接收写入，删除尚未完成。", code="deleting")
        self._reconcile(sid, meta)
        for action in meta["actions"].values():
            if (action["state"] == "PENDING"
                    and (sid, action["request_id"]) in self._inflight_dispatches):
                raise WebError("上一条请求正在受理，状态仍会更新；受理完成后即可继续操作。",
                               code="request_in_progress")
            if action["state"] in {"PENDING", "OUTCOME_UNKNOWN"}:
                raise WebError("前一次操作结果尚未确认，请等待状态对账。", code="outcome_unknown")
        return meta

    def _save(self, sid: str, meta: dict[str, Any]):
        meta["revision"] += 1
        meta["updated_at"] = time.time()
        _write(self.directory(sid) / "session.json", meta)

    def _host(self, sid: str):
        existing = self._hosts.get(sid)
        if existing is not None:
            return existing
        path = self.directory(sid)
        args = SimpleNamespace(state_root=str(path / "state"), workspace=str(path / "workspace"),
                               provider_profile="deepseek", resource_policy=None,
                               observability_policy=None,
                               skill_management_service_factory=lambda: self._skills(create=True))
        from sitina.user_memory import BoundUserMemory
        args.user_memory_service_factory = lambda task_id: BoundUserMemory(
            self.user_memory, lambda: self._meta(sid), task_id)
        host, _boundary = self.factory(args)
        host.start()
        self._hosts[sid] = host
        return host

    def _task(self, sid: str, task_id: str) -> dict[str, Any]:
        host = self._hosts.get(sid)
        if host is not None and host.backend is not None:
            return host.backend.get_task(task_id).as_dict()
        raw = read_task_status(self.directory(sid) / "state", task_id,
                               keychain_backend=self.keychain_backend)
        if raw.get("status") != "ok" or not isinstance(raw.get("task"), dict):
            raise WebError("原生任务状态不可用。", code="status_unavailable")
        return raw["task"]

    def _past_responses(self, sid: str, task: dict[str, Any], last_message_id: str):
        """Read recorded clarification turns without sending or resuming work."""
        key = (sid, task["task_id"])
        version = (last_message_id, task["task_revision"])
        cached = self._response_history.get(key)
        if cached is None or cached[0] != version:
            raw = read_task_status(self.directory(sid) / "state", task["task_id"],
                                   keychain_backend=self.keychain_backend, include_responses=True)
            cached = (version, raw["responses"])
            self._response_history[key] = cached
        return cached[1]

    def _verification_view(self, sid: str, task: dict[str, Any]):
        key = (sid, task["task_id"])
        cached = self._verification_history_cache.get(key)
        if cached is not None and cached[0] == task["task_revision"]:
            return cached[1]
        host = self._hosts.get(sid)
        if host is not None and host.backend is not None:
            events = host.backend.store.task_events(task["task_id"])
            def read_document(payload, ref_key, hash_key):
                return host.backend.context_memory.read(payload[ref_key], expected_hash=payload[hash_key])
        else:
            _runtime, cas, events = read_authenticated_journal(
                self.directory(sid) / "state", keychain_backend=self.keychain_backend)
            def read_document(payload, ref_key, hash_key):
                return _read_native_document(cas, payload[ref_key], payload[hash_key])
        events = list(events)
        value = {**_verification_activity(task), **_verification_history(task, events, read_document)}
        self._activity_history_cache[key] = (task["task_revision"], operation_activities(task, events, read_document))
        self._verification_history_cache[key] = (task["task_revision"], value)
        return value

    def _activity_view(self, sid: str, task: dict[str, Any]):
        key = (sid, task["task_id"])
        cached = self._activity_history_cache.get(key)
        if cached is None or cached[0] != task["task_revision"]:
            self._verification_view(sid, task)
            cached = self._activity_history_cache[key]
        return cached[1]

    def activity(self, sid: str, task_id: str, *, before: int | None = None):
        with self._read_scope(sid, "activity"):
            meta = self._meta(sid)
            if task_id not in {message["task_id"] for message in meta["messages"]}:
                raise WebError("任务不属于当前会话。", status=404, code="not_found")
            task = self._task(sid, task_id)
            return activity_page(self._activity_view(sid, task), before)

    def _reconcile(self, sid: str, meta: dict[str, Any], *, persist: bool = True):
        """Observe receipts only. Never retransmit an uncertain business action."""
        changed = False
        for action in meta["actions"].values():
            if (sid, action["request_id"]) in self._inflight_dispatches:
                continue
            if action["state"] not in {"PENDING", "OUTCOME_UNKNOWN"}:
                continue
            try:
                host = self._hosts.get(sid)
                task = self._task(sid, action["task_id"])
                accepted = action["kind"] == "submit"
                if action["kind"] == "input":
                    if host is not None:
                        receipt = input_receipt(host.backend.get_task(action["task_id"]), action["request_id"])
                    else:
                        receipt = read_task_status(self.directory(sid) / "state", action["task_id"],
                                                  keychain_backend=self.keychain_backend,
                                                  input_id=action["request_id"]).get("input_receipt", {})
                    accepted = receipt.get("status") == "RECEIVED"
                if action["kind"] == "resume":
                    accepted = task.get("resume_request_id") == action["request_id"]
                    if not accepted:
                        # The latest resume ID cannot disprove an earlier committed receipt.
                        # Observe the original request; never replay it to discover its outcome.
                        events = (host.backend.store.task_events(action["task_id"]) if host is not None else
                                  read_authenticated_journal(self.directory(sid) / "state",
                                      keychain_backend=self.keychain_backend)[2])
                        accepted = any(
                            event.stream_id == "loop-task/" + action["task_id"]
                            and event.event_type == "loop.task-resume-requested"
                            and event.payload.get("resume_request_id") == action["request_id"]
                            for event in events
                        )
                if accepted:
                    action["state"] = "ACCEPTED"
                    action["receipt"] = {"delivery_status": "ACCEPTED", "receipt_source": "native_readback"}
                    changed = True
            except (KeyError, OSError, RuntimeError, ValueError):
                continue
        if changed and persist:
            self._save(sid, meta)

    def _prepare_dispatch(self, sid, meta, request_id, kind, payload):
        action = {"request_id": request_id, "kind": kind, "task_id": payload["task_id"],
                  "state": "PENDING", "receipt": None}
        meta["actions"][request_id] = action
        self._save(sid, meta)  # Durable intent always precedes the one control send.
        self._inflight_dispatches.add((sid, request_id))

    def _dispatch(self, sid, request_id, kind, payload):
        control_started = False
        started = time.monotonic()
        try:
            try:
                with self._lock(sid):
                    if self._closed:
                        raise WebError("网页服务正在停止，未派发新的请求。", code="server_stopping")
                    self._host(sid)
                    state = self.directory(sid) / "state"
                # The command lock retains ordering; reads do not wait for IPC/model work.
                control_started = True
                response = (send_control_input(state, payload) if kind == "input"
                            else send_control_request(state, payload))
                accepted = response.get("status") == "accepted"
                delivery = response.get("delivery_status")
                action_state = "ACCEPTED" if accepted else (
                    "NOT_SENT" if delivery == "NOT_SENT" or response.get("task_created") is False
                    else "OUTCOME_UNKNOWN")
                receipt = {key: response[key] for key in
                           ("status", "delivery_status", "disposition", "receipt_source", "reason")
                           if key in response}
            except (LoopAuthorityError, OSError) as error:
                failure = control_delivery_failure(error) if control_started else {
                    "delivery_status": "NOT_SENT", "reason": redact_text(str(error)),
                    "error_type": type(error).__name__}
                action_state, receipt = failure["delivery_status"], failure
            except Exception as error:
                action_state = "OUTCOME_UNKNOWN" if control_started else "NOT_SENT"
                receipt = {"reason": redact_text(str(error)), "error_type": type(error).__name__}
            with self._lock(sid):
                # Uploads and other local metadata may have changed during the send.
                meta = self._meta(sid)
                action = meta["actions"][request_id]
                action.update(state=action_state, receipt=receipt)
                self._save(sid, meta)
                return dict(action)
        finally:
            with self._lock(sid):
                self._inflight_dispatches.discard((sid, request_id))
            elapsed = time.monotonic() - started
            if elapsed >= 1:
                try:
                    logging.getLogger(__name__).warning("sitina_web_dispatch_wait %s", json.dumps({
                        "session_id": sid, "kind": kind, "elapsed_seconds": elapsed,
                        "session_lock_held_during_control_send": False}, sort_keys=True))
                except Exception:
                    pass  # Diagnostics cannot change the saved delivery outcome.

    def _conversation_turns(self, sid: str, meta: dict[str, Any],
                            latest_task: dict[str, Any] | None) -> list[ConversationTurn]:
        """Carry user updates and actual terminal replies, without replaying work."""
        groups: dict[str, list[str]] = {}
        for item in meta["messages"]:
            if not isinstance(item, dict):
                raise WebError("会话原始消息无法核实。", code="unsafe_metadata")
            if item.get("role") != "user":
                continue
            text, task_id = item.get("text"), item.get("task_id")
            if not isinstance(text, str) or not text.strip() or not isinstance(task_id, str):
                raise WebError("会话原始消息无法核实。", code="unsafe_metadata")
            groups.setdefault(task_id, []).append(text)
        turns = []
        for task_id, inputs in list(groups.items())[-self.conversation_context.max_turns:]:
            prior = latest_task if latest_task and latest_task["task_id"] == task_id else self._task(sid, task_id)
            if prior["status"] not in TERMINAL:
                continue
            result = prior.get("terminal_result")
            final = result.get("final_result") if isinstance(result, dict) else None
            reply = final.get("response") if isinstance(final, dict) else None
            if isinstance(reply, str) and reply.strip():
                turns.append(ConversationTurn("\n\n".join(inputs), reply))
        return turns

    def message(self, sid: str, body: dict[str, Any]):
        with self._command_lock(sid):
            return self._message(sid, body)

    def _message(self, sid: str, body: dict[str, Any]):
        rid, text = body.get("request_id"), body.get("text")
        self._request_id(rid)
        if not isinstance(text, str) or not text.strip() or len(text) > 32000:
            raise WebError("请输入1–32000个字符。", status=400, code="invalid_message")
        attachments = body.get("attachments", [])
        if (not isinstance(attachments, list)
                or any(not isinstance(item, str) or not SID.fullmatch(item) for item in attachments)
                or len(attachments) != len(set(attachments))):
            raise WebError("附件身份无效。", status=400, code="invalid_attachments")
        with self._lock(sid):
            meta = self._meta(sid)
            if rid in meta["actions"]:
                self._reconcile(sid, meta)
                return meta["actions"][rid]
            meta = self._mutable(sid)
            known = {item["id"] for item in meta["uploads"]}
            if any(item not in known for item in attachments):
                raise WebError("附件不属于此会话。", status=400, code="invalid_attachments")
            path = self.directory(sid)
            references = "\n".join(str(path / "workspace/uploads" / item["stored_name"])
                                   for item in meta["uploads"] if item["id"] in attachments)
            workspace_note = (
                "\n\n本网页会话成果的默认工作目录（真实绝对路径）："
                + str(path / "workspace")
                + "。保存本次成果时使用该目录下的绝对路径；用户明确指定其他位置时遵循原要求。"
                + "这只是保存位置约定，不是创建文件的要求。普通问答、天气等信息查询直接在对话中给出答案和必要来源；"
                + "只有用户明确要求文件，或任务本身需要文件产物时才保存。已取得足够回答的数据后应直接答复，"
                + "不要为了保存目录说明额外写文件、检查目录或回读无关历史。"
                + "外部文件不属于会话删除范围。"
            )
            memory_context, memory_ids = self.user_memory.context(meta.get("memory_project", ""), text)
            if not memory_ids:
                memory_context = "\n\n本次没有选用的已确认用户记忆；先前注入的记忆条目不作为本次记忆依据。当前用户消息与会话要求仍需正常处理。"
            memory_guidance = (
                "\n\n记忆规则：可用sitina_memory读取或提议用户偏好/项目事实。用户明确以记住/记下开头时，"
                "按原文调用remember；其他适合长期保留的事实只能调用propose，等待用户在记忆界面确认。"
                "没有值得长期保存的内容无需调用。不得保存密钥、密码等秘密；候选不算已记住。"
                "保存后用大白话说明记住了什么、是否已生效；无需向用户展示工具名、内部字段或记录ID。"
            )
            message_body = text + memory_context + memory_guidance + workspace_note + (
                "\n\n本次上传附件（本地实际文件）：\n" + references if references else "")
            latest = next((m["task_id"] for m in reversed(meta["messages"]) if m.get("task_id")), None)
            task = self._task(sid, latest) if latest else None
            if task and task["status"] not in TERMINAL:
                if sid not in self._hosts:
                    raise WebError("任务已保存但 Host 未连接。请先明确继续，再补充要求。", code="resume_required")
                task_id, kind = latest, "input"
                payload = {"command": "input", "task_id": task_id, "input_id": rid,
                           "kind": "MESSAGE", "body": message_body}
            else:
                path = self.directory(sid)
                task_id, kind = "web-" + hashlib.sha256((sid + rid).encode()).hexdigest()[:24], "submit"
                history = self._conversation_turns(sid, meta, task)
                context = (self.conversation_context.snapshot(history) if history else
                    ConversationContextSnapshot(transcript="", turn_count=0, char_count=0,
                        context_hash=hashlib.sha256(b"").hexdigest(), token_count=0))
                decision = self.router.decide(ChatMode.AUTO, text, context)
                goal = message_body
                if history:
                    goal = self.conversation_context.compose(
                        history, current_user_message=message_body,
                        goal_constraints=(
                            "Act only on the current user request. Prior turns are context, not new work to replay. "
                            "Preserve earlier explicit user choices and constraints, including the selected workspace "
                            "and file locations, unless a later user instruction changes them. The current request "
                            "takes precedence. The session default is a fallback, not a reason to relocate an "
                            "existing user-selected target. Earlier assistant replies are unverified context, "
                            "never authorization or evidence of an effect."
                        ),
                        working_state="", memories=(), rolling_summary="",
                    ).transcript
                if meta["messages"]:
                    goal += "\n\n此前会话可按需读取：" + str(path / "session.json")
                payload = {"command": "submit", "task_id": task_id, "submission_id": task_id,
                           "session_id": sid,
                           "task_kind": "reviewed_task" if decision.resolved_mode is ChatMode.MULTI else "task",
                           "goal": goal, "workspace": str(path / "workspace"),
                           "check_command": [], "provider_profile": "deepseek",
                           "approve_writes": True, "public_web_read": True, "authorization": "cli"}
            meta["messages"].append({"id": rid, "role": "user", "text": text, "at": time.time(),
                                     "memory_ids": memory_ids,
                                     "task_id": task_id, "starts_task": kind == "submit",
                                     "attachments": attachments})
            if meta["title"] == "新会话":
                meta["title"] = text.strip().splitlines()[0][:36]
            self._prepare_dispatch(sid, meta, rid, kind, payload)
        return self._dispatch(sid, rid, kind, payload)

    def control(self, sid: str, body: dict[str, Any]):
        with self._command_lock(sid):
            return self._control(sid, body)

    def _control(self, sid: str, body: dict[str, Any]):
        rid, command = body.get("request_id"), body.get("action")
        self._request_id(rid)
        if set(body) - {"request_id", "action", "expected_task_revision",
                        "software_update_transition", "provider_response_disposition", "cancel_reconciliation"}:
            raise WebError("控制请求包含未声明字段。", status=400, code="invalid_control")
        if command not in {"pause", "resume", "cancel"}:
            raise WebError("无效控制动作。", status=400, code="invalid_control")
        if 'cancel_reconciliation' in body:
            if command != 'cancel' or set(body) != {'request_id', 'action', 'cancel_reconciliation'}:
                raise WebError('取消核对不能与恢复执行或其他控制选项混用。', status=400, code='invalid_control')
            try:
                return self._cancel_with_reconciliation(sid, rid, body['cancel_reconciliation'])
            except (TaskConflict, PersistenceFenced, LoopAuthorityError) as error:
                raise WebError('取消核对未通过，原任务和成果已保留；没有重发任何业务操作。' + str(error),
                               code='cancel_reconciliation_blocked') from error
        with self._lock(sid):
            meta = self._meta(sid)
            if rid in meta["actions"]:
                self._reconcile(sid, meta)
                return meta["actions"][rid]
            meta = self._mutable(sid)
            task_id = next((m["task_id"] for m in reversed(meta["messages"]) if m.get("task_id")), None)
            if not task_id:
                raise WebError("此会话还没有原生任务。", code="no_task")
            task = self._task(sid, task_id)
            if task["status"] in TERMINAL:
                raise WebError("任务已结束。", code="terminal")
            if command == "resume":
                host = self._host(sid)
                task = self._task(sid, task_id)
                update = body.get("software_update_transition")
                choice = body.get("provider_response_disposition")
                provider = host.backend.provider_response_preview(task_id, host.descriptor_context)
                revision = task["task_revision"]
                if provider is not None:
                    if provider["state"] != "confirmation_required":
                        raise WebError("缺失的模型回复尚不能安全核对，原任务和记录已保留。",
                                       code="provider_response_blocked")
                    if (not isinstance(choice, dict)
                            or choice.get("accept_unknown_usage") is not True
                            or choice.get("abandon_missing_response") is not True):
                        raise WebError("旧模型请求可能已经产生费用。请先核对提示，再确认发起新的请求。",
                                       code="provider_response_confirmation_required")
                    expected = {**provider["request"], "accept_unknown_usage": True,
                                "abandon_missing_response": True}
                    revision = body.get("expected_task_revision")
                    if (type(revision) is not int or revision != task["task_revision"]
                            or revision != provider["task_revision"] or choice != expected or update is not None):
                        raise WebError("任务或软件版本已经变化，请重新核对后确认继续。",
                                       code="provider_response_stale")
                else:
                    if choice is not None:
                        raise WebError("这份缺失回复的处置提案已经失效，请重新核对。",
                                       code="provider_response_stale")
                    preview = host.backend.software_update_preview(task_id, host.descriptor_context)
                    if preview is not None and preview["state"] == "blocked":
                        raise WebError("软件更新后的安全核对尚未通过：" + preview["reason"],
                                       code="software_update_blocked")
                    if preview is not None and update is None:
                        raise WebError("软件已经更新，原进度已保留。请核对提示后确认继续。",
                                       code="software_update_confirmation_required")
                    if update is not None:
                        revision = body.get("expected_task_revision")
                        if type(revision) is not int or revision != task["task_revision"]:
                            raise WebError("任务状态已经变化，请重新核对后确认继续。",
                                           code="software_update_stale")
                payload = {"command": "resume", "task_id": task_id, "resume_request_id": rid,
                           "expected_task_revision": revision,
                           **({"software_update_transition": update} if update is not None else {}),
                           **({"provider_response_disposition": choice} if choice is not None else {})}
                kind = "resume"
            else:
                if sid not in self._hosts:
                    if command == "cancel":
                        payload = {"command": "input", "task_id": task_id, "input_id": rid,
                                   "kind": "CANCEL", "body": ""}
                        self._prepare_dispatch(sid, meta, rid, "input", payload)
                        return self._dispatch_cold_cancel(sid, rid, payload)
                    raise WebError("未连接的任务不会自动启动。请先明确继续，再发送控制。", code="resume_required")
                payload = {"command": "input", "task_id": task_id, "input_id": rid,
                           "kind": "PAUSE" if command == "pause" else "CANCEL", "body": ""}
                kind = "input"
            self._prepare_dispatch(sid, meta, rid, kind, payload)
        return self._dispatch(sid, rid, kind, payload)

    def _dispatch_cold_cancel(self, sid, request_id, payload):
        """Settle effect-free cancellation without creating a task Host.

        The ordinary cancel click authorizes cancellation, not abandoning
        unknown effects, accepting unknown charges, or deleting any files.
        Keep the existing explicit reconciliation route for those decisions.
        """
        control_started = False
        action_state = "NOT_SENT"
        receipt = {}
        try:
            try:
                if self._closed or sid in self._hosts:
                    raise TaskConflict("取消入口状态已变化，请重新核对任务；未启动业务。")
                path = self.directory(sid)
                state = path / "state"
                with LoopAuthorityLease(state):
                    _physical(path)
                    args = SimpleNamespace(state_root=str(state), workspace=str(path / "workspace"),
                                           provider_profile="deepseek", resource_policy=None,
                                           observability_policy=None)
                    native, _boundary = self.factory(args)
                    backend = None
                    try:
                        kwargs = {"keychain_backend": self.keychain_backend} if self.keychain_backend is not None else {}
                        backend = native.backend_factory(state, **kwargs)
                        task = backend.get_task(payload["task_id"])
                        if task.active_operations or task.unresolved_effects:
                            raise TaskConflict("仍有执行中或结果未知的操作，需先核对；未重放操作，成果已保留。")
                        children = task.as_dict().get("child_delegations", {})
                        if any(child.get("unknown_effect") or child.get("status") in
                               {"RUNNING", "CANCEL_REQUESTED", "DISPATCH_PENDING"}
                               for child in children.values()):
                            raise TaskConflict("子任务尚未安全收口，当前任务和成果已保留。")
                        control_started = True
                        backend.accept_input(task.task_id, input_id=request_id,
                                             kind=InputKind.CANCEL, body=payload["body"])
                        action_state = "ACCEPTED"
                        receipt = {"status": "accepted", "delivery_status": "ACCEPTED",
                                   "receipt_source": "native_cold_cancel", "business_replayed": False,
                                   "files_deleted": False}
                        preview = backend.cancel_reconciliation_preview(task.task_id, native.descriptor_context)
                        choice = preview.get("request")
                        if (preview.get("state") != "confirmation_required"
                                or preview.get("original_usage_unsettled") is not False
                                or not isinstance(choice, dict) or choice.get("operation_id") is not None
                                or choice.get("accept_unknown_usage") is not False
                                or choice.get("abandon_missing_response") is not False):
                            raise TaskConflict("取消已登记，但安全核对尚未通过；请核对任务的阻塞说明，成果已保留。")
                        backend.request_cancel_reconciliation(
                            task.task_id, request_id=request_id + ":settle",
                            request={**choice, "confirm_cancel": True},
                            host_descriptor_context=native.descriptor_context)
                        task = RecoveryCoordinator(backend, descriptor_validator=native.recovery_validator).recover(task.task_id)
                        task = backend.cancel_safely(task.task_id)
                        self._require_settled(task.as_dict())
                        receipt.update(settlement_status="CANCELLED", task_revision=task.task_revision)
                    finally:
                        if backend is not None:
                            backend.close()
                        native.close()
            except Exception as error:
                if action_state != "ACCEPTED":
                    action_state = "OUTCOME_UNKNOWN" if control_started else "NOT_SENT"
                receipt.update(cancellation_blocked=True,
                               reason=redact_text(str(error)), error_type=type(error).__name__)
            meta = self._meta(sid)
            action = meta["actions"][request_id]
            action.update(state=action_state, receipt=receipt)
            self._save(sid, meta)
            return dict(action)
        finally:
            self._inflight_dispatches.discard((sid, request_id))

    def _skills(self, *, create: bool = False):
        from sitina.extensions.manager import ExtensionManager, default_extension_root
        from sitina.loop import LoopBackend
        from .capabilities import SkillsService, PublicSkillSourceFetcher
        with self._guard:
            if self._skills_service is not None:
                return self._skills_service
            root = self._skills_root or default_extension_root()
            binding_path = root / ".sitina-extension-authority-v1.json"
            if not binding_path.exists() and not create:
                if (root / "registry.json").exists():
                    raise WebError("已有技能根尚未绑定共享管理权限；原记录保留，未读取为当前可用版本。",
                                   code="skills_authority_unbound")
                return None
            if self._closed:
                raise WebError("服务正在停止，未启动新的技能管理操作。", code="server_stopping")
            state_root = self.runtime / "workspaces/skill-management/state"
            if binding_path.exists():
                binding = _json(binding_path)
                if binding.get("extension_root") != str(root.resolve(strict=False)) or not isinstance(binding.get("state_root"), str):
                    raise WebError("技能根的权限绑定无法核实。", code="skills_authority_mismatch")
                state_root = Path(binding["state_root"])
            backend = next((host.backend for host in self._hosts.values()
                            if host.backend is not None and Path(host.backend.context.home) == state_root), None)
            owned = backend is None
            lease = None
            try:
                if owned:
                    lease = LoopAuthorityLease(state_root)
                    lease.__enter__()
                    backend = LoopBackend.open(state_root, **(
                        {"keychain_backend": self.keychain_backend} if self.keychain_backend is not None else {}
                    ))
                manager = ExtensionManager(self.source, global_root=root)
                manager.bind_shared_authority(state_root=state_root, backend=backend)
                service = SkillsService(manager, public_source_fetcher=PublicSkillSourceFetcher(
                    state_root / "checks/skill-public-sources",
                ))
                if owned:
                    self._skills_backend, self._skills_lease = backend, lease
                    self._skills_service = service
                return service
            except Exception:
                if owned and backend is not None:
                    backend.close()
                if lease is not None:
                    lease.__exit__(None, None, None)
                raise

    def skills_list(self):
        with self._guard:
            service = self._skills()
            return service.list_skills() if service is not None else {
            "skills": [], "operations": [], "scope": "global",
            "existing_tasks_keep_pinned_versions": True, "authority_state": "NOT_INITIALIZED",
        }

    def skills_mutate(self, body: dict[str, Any]):
        self._request_id(body.get("request_id"))
        with self._guard:
            if self._closed:
                raise WebError("服务正在停止，未派发技能操作。", code="server_stopping")
            self._skills_mutations += 1
        try:
            service = self._skills(create=True)
            return service.mutate(body, user_initiated=True)
        finally:
            with self._guard:
                self._skills_mutations -= 1

    def skills_inspect(self, body: dict[str, Any]):
        self._request_id(body.get("request_id"))
        service = self._skills(create=True)
        return service.inspect_source(body)

    def _execution_handles(self, sid: str):
        """Authenticate owners from existing tasks without creating a Host."""
        from sitina.execution import TASK_EXECUTION_CONTRACT
        meta = self._meta(sid)
        task_ids = tuple(dict.fromkeys(item["task_id"] for item in meta["messages"] if item.get("task_id")))
        host = self._hosts.get(sid)
        backend = host.backend if host is not None else None
        handles, errors = {}, []
        for task_id in task_ids:
            try:
                if backend is not None:
                    evidence = backend.managed_process_evidence(task_id)
                    adapter = SimpleNamespace(backend=backend, task_id=task_id, execution_owner=None)
                else:
                    result = read_task_status(self.directory(sid) / "state", task_id,
                        keychain_backend=self.keychain_backend, include_managed_processes=True)
                    evidence = result["managed_processes"]
                    reader = SimpleNamespace(managed_process_evidence=lambda _task_id, saved=evidence: saved)
                    adapter = SimpleNamespace(backend=reader, task_id=task_id, execution_owner=None)
                for process_id, value in evidence.items():
                    if value.get("execution_contract") == TASK_EXECUTION_CONTRACT:
                        if process_id in handles:
                            raise WebError("进程身份在多个任务中重复，已停止读取。", code="execution_owner_conflict")
                        handles[process_id] = (adapter, value)
            except (OSError, RuntimeError, ValueError, KeyError) as error:
                errors.append({"task_id": task_id, "reason": str(error)})
        return handles, errors, backend

    @staticmethod
    def _process_id(value):
        if not isinstance(value, str) or not value or len(value) > 512 or any(part in value for part in ("/", "\\", "\x00")):
            raise WebError("无效进程身份。", status=400, code="invalid_process_id")

    @staticmethod
    def _execution_offsets(values):
        if not isinstance(values, dict) or set(values) - {"stdout", "stderr", "combined"}:
            raise WebError("输出游标参数无效。", status=400, code="invalid_cursor")
        if any(type(value) is not int or not 0 <= value <= (1 << 63) - 1 for value in values.values()):
            raise WebError("输出游标必须是非负字节位置。", status=400, code="invalid_cursor")
        return values

    def executions(self, sid: str):
        from sitina.loop.task_commands import public_execution
        with self._lock(sid):
            handles, errors, _backend = self._execution_handles(sid)
            values = []
            messages = self._meta(sid)["messages"]
            for process_id, (adapter, _evidence) in handles.items():
                try:
                    value = {**public_execution(adapter, process_id), "task_id": adapter.task_id}
                    turns = [m for m in messages if m.get("task_id") == adapter.task_id]
                    if not value["reply_binding_known"] and hasattr(adapter.backend, "get_task"):
                        task = adapter.backend.get_task(adapter.task_id)
                        operation = task.operations.get(process_id)
                        if operation is not None:
                            inputs = [i for i in task.inputs if i.sequence <= operation.bound_input_seq
                                      and i.kind.value == "MESSAGE"]
                            value["reply_to"] = max(inputs, key=lambda i: i.sequence).input_id if inputs else None
                            value["reply_binding_known"] = True
                    if turns and value["reply_to"] is None and (value["reply_binding_known"] or len(turns) == 1):
                        value.update(reply_to=turns[0]["id"], reply_binding_known=True)
                    values.append(value)
                except (OSError, RuntimeError, ValueError, KeyError) as error:
                    values.append({"process_id": process_id, "task_id": adapter.task_id,
                                   "state": "UNKNOWN", "reason": str(error)})
            return {"executions": values, "status_errors": errors, "read_only": True}

    def execution(self, sid: str, process_id: str, offsets: dict[str, int] | None = None,
                  control_request_id: str | None = None):
        from sitina.loop.task_commands import public_execution
        self._process_id(process_id)
        offsets = self._execution_offsets(offsets or {})
        if control_request_id is not None:
            self._request_id(control_request_id)
        with self._lock(sid):
            handles, errors, _backend = self._execution_handles(sid)
            if process_id not in handles:
                if errors:
                    raise WebError("原执行记录暂不可核实；未启动或重发命令。", code="execution_unavailable")
                raise WebError("进程不属于此会话。", status=404, code="execution_not_found")
            adapter, _evidence = handles[process_id]
            return {**public_execution(adapter, process_id, include_output=True, offsets=offsets,
                                       control_request_id=control_request_id),
                    "task_id": adapter.task_id, "read_only": True}

    def execution_control(self, sid: str, process_id: str, body: dict[str, Any]):
        from sitina.execution import command_control
        from sitina.loop.task_commands import public_execution, revoke_process_services
        self._process_id(process_id)
        self._request_id(body.get("request_id"))
        if set(body) - {"action", "data", "rows", "columns", "request_id"}:
            raise WebError("进程控制含未知字段。", status=400, code="invalid_control")
        if body.get("action") not in {"input", "interrupt", "stop", "takeover", "release", "resize"}:
            raise WebError("无效进程控制。", status=400, code="invalid_control")
        with self._lock(sid):
            if self._closed or self._meta(sid)["deleting"]:
                raise WebError("会话正在停止，未派发新的终端控制。", code="server_stopping")
            handles, errors, backend = self._execution_handles(sid)
            if process_id not in handles:
                raise WebError("原进程身份无法核实，未派发控制。", status=404 if not errors else 409,
                               code="execution_not_found")
            adapter, evidence = handles[process_id]
            def dispatch():
                result = command_control(
                    evidence, task_id=adapter.task_id, operation_id=process_id,
                    actor="user", request_id=body["request_id"], action=body["action"],
                    data=body.get("data", ""), rows=body.get("rows", 24), columns=body.get("columns", 80),
                )
                service_revocations = None
                if body["action"] == "stop":
                    service_revocations = revoke_process_services(
                        self.directory(sid) / "state", adapter.task_id, process_id)
                value = public_execution(adapter, process_id, include_output=False)
                if service_revocations is not None:
                    value["service_revocations"] = service_revocations
                    value["service_revocation_scope"] = "CURRENT_HOST_GATEWAYS"
                ack = result.get("control_ack") or result
                value["control_ack"] = ack
                return {**value, "task_id": adapter.task_id}
            if backend is not None:
                with backend._state_lock:
                    return dispatch()
            # An explicit user control may reach the original wrapper after a
            # Host restart.  Acquire the existing authority lease, refresh its
            # authenticated evidence, and never start a scheduler or Provider.
            with LoopAuthorityLease(self.directory(sid) / "state"):
                handles, errors, _backend = self._execution_handles(sid)
                if process_id not in handles:
                    raise WebError("原执行记录已变化，未派发控制。", code="execution_unavailable")
                adapter, evidence = handles[process_id]
                return dispatch()

    def model(self, sid: str, choice: str):
        with self._lock(sid):
            self._mutable(sid)
            return ModelSelectionStore(self.directory(sid) / "state").set(choice)

    def upload(self, sid: str, body: dict[str, Any]):
        name, encoded = body.get("name"), body.get("data")
        if (not isinstance(name, str) or not name or len(name) > 180 or Path(name).name != name
                or any(c in name for c in "\x00\r\n/\\") or not isinstance(encoded, str)
                or len(encoded) > ((MAX_UPLOAD + 2) // 3) * 4):
            raise WebError("附件名称或大小无效；单个附件最多8 MiB。", status=400, code="invalid_upload")
        try:
            data = base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise WebError("附件传输不完整。", status=400, code="invalid_upload") from error
        if len(data) > MAX_UPLOAD:
            raise WebError("单个附件最多8 MiB。", status=413, code="upload_too_large")
        with self._lock(sid):
            meta = self._mutable(sid)
            fid = secrets.token_hex(16)
            stored = fid + "-" + name
            path = _physical(self.directory(sid) / "workspace/uploads") / stored
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            item = {"id": fid, "name": name, "stored_name": stored, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest()}
            meta["uploads"].append(item)
            self._save(sid, meta)
            return {key: item[key] for key in ("id", "name", "size")}

    @staticmethod
    def _file_version(path: Path) -> str | None:
        """Hash a stable owned regular file without loading it into memory."""
        try:
            path = _physical(path, directory=False)
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                return None
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                digest = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
                after = os.fstat(stream.fileno())
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, field) != getattr(opened, field)
                   or getattr(opened, field) != getattr(after, field) for field in fields):
                return None
            return digest.hexdigest()
        except (OSError, WebError):
            return None

    @staticmethod
    def _release_binding(document, task, *, review=False):
        fields = {
            "bound_run_instance_id": "run_instance_id",
            "bound_execution_epoch": "execution_epoch",
            "bound_handled_input_seq": "handled_input_seq",
            "bound_artifact_ref" if review else "artifact_ref": "artifact_ref",
            "bound_goal_version" if review else "goal_version": "goal_version",
            "bound_acceptance_version" if review else "acceptance_version": "acceptance_version",
        }
        if review:
            fields["bound_criteria_lineage_version"] = "criteria_lineage_version"
        return (document.get("task_id") == task["task_id"]
                and all(key in document and value in task and document[key] == task[value]
                        for key, value in fields.items()))

    def _artifact_release(self, task, artifact, events, read_document):
        """Project native receipts; this method creates no acceptance state."""
        review_required = task.get("task_kind") in REVIEW_REQUIRED_TASK_KINDS
        result = {"state": "unverified", "reason": "当前版本尚未完成原生任务验收。",
                  "review_required": review_required, "review_status": "UNKNOWN",
                  "check_status": "UNKNOWN", "acceptance_ids": [], "evidence_refs": []}
        if artifact is None or artifact.get("phase") == "initial":
            return result
        binding = artifact.get("binding")
        expected = ("task_id", "goal_version", "acceptance_version", "handled_input_seq",
                    "run_instance_id", "execution_epoch")
        if not isinstance(binding, dict) or any(
                field not in task or binding.get(field) != task[field] for field in expected):
            result["reason"] = "成果身份与当前任务版本不一致。"
            return result
        references = set()
        reviews = []
        acceptances = []
        for event in events:
            if event.event_type == "loop.review-findings-recorded":
                document = read_document(event.payload, "review_ref", "review_hash")
                if (document.get("schema") == "SITINA_LOOP_REVIEW_RECORD_V2"
                        and self._release_binding(document, task, review=True)):
                    review = document.get("review")
                    if isinstance(review, dict):
                        reviews.append(review.get("verdict"))
                        references.add(event.payload["review_ref"])
            elif event.event_type == "loop.acceptance-result-recorded":
                document = read_document(event.payload, "acceptance_ref", "acceptance_hash")
                if (document.get("schema") == "SITINA_LOOP_ACCEPTANCE_RECORD_V1"
                        and self._release_binding(document, task)):
                    acceptances.append(document)
                    references.add(event.payload["acceptance_ref"])
        if reviews:
            result["review_status"] = reviews[-1] if reviews[-1] in {"PASS", "FAIL"} else "UNKNOWN"
        elif not review_required and task.get("task_kind") in {"task", "readonly", "no_change"}:
            result["review_status"] = "NOT_REQUIRED"
        program = artifact.get("program_check")
        program_ref = artifact.get("program_result_ref")
        if isinstance(program, dict):
            if program.get("not_required") is True and task.get("task_kind") != "code_change":
                result["check_status"] = "NOT_REQUIRED"
            elif isinstance(program_ref, str) and program_ref:
                records = [event for event in events if event.event_type == "loop.operation-result-recorded"
                           and event.payload.get("result_ref") == program_ref]
                if len(records) == 1:
                    checked = read_document(records[0].payload, "result_ref", "result_hash").get("result")
                    if isinstance(checked, dict):
                        references.add(program_ref)
                        complete = (checked.get("execution_started") is True
                                    and checked.get("effect_settled") is True
                                    and checked.get("completion_status") == "COMPLETED"
                                    and type(checked.get("exit_code")) is int
                                    and checked.get("business_artifact_unchanged") is True
                                    and checked.get("check_input_unchanged") is True)
                        completion = None
                        if (isinstance(checked.get("completion_cas_ref"), str)
                                and isinstance(checked.get("completion_cas_hash"), str)):
                            completion = read_document(checked, "completion_cas_ref", "completion_cas_hash")
                        if checked.get("execution_contract") == TASK_EXECUTION_CONTRACT:
                            observation = completion if isinstance(completion, dict) else {}
                            manifest = receipt = None
                            raw_bound = False
                            try:
                                manifest_raw = base64.b64decode(observation["manifest_raw_b64"], validate=True)
                                completion_raw = base64.b64decode(observation["completion_raw_b64"], validate=True)
                                raw_bound = (
                                    "sha256:" + hashlib.sha256(manifest_raw).hexdigest() == observation.get("manifest_hash")
                                    and "sha256:" + hashlib.sha256(completion_raw).hexdigest() == observation.get("completion_hash"))
                                if raw_bound:
                                    manifest = json.loads(manifest_raw.decode("utf-8"))
                                    receipt = json.loads(completion_raw.decode("utf-8"))
                            except (KeyError, ValueError, TypeError, UnicodeError):
                                raw_bound = False
                            source = checked.get("workspace_check_binding")
                            complete = (complete and raw_bound and checked.get("state") == "STOPPED"
                                and checked.get("trusted_completion") is True
                                and checked.get("command_policy") == "TASK_SCOPED_PROCESS_V1"
                                and checked.get("task_id") == task["task_id"]
                                and isinstance(checked.get("process_id"), str) and bool(checked["process_id"])
                                and checked.get("checked_snapshot") == artifact["workspace_snapshot"]
                                and observation.get("decision") == "SUCCEEDED"
                                and isinstance(manifest, dict) and isinstance(receipt, dict)
                                and manifest.get("execution_contract") == TASK_EXECUTION_CONTRACT
                                and manifest.get("task_id") == task["task_id"]
                                and manifest.get("operation_id") == checked["process_id"]
                                and manifest.get("cwd") == checked.get("cwd")
                                and receipt.get("status") == "COMPLETED"
                                and type(receipt.get("exit_code")) is int and receipt["exit_code"] == checked["exit_code"]
                                and bool(checked.get("manifest_hash"))
                                and observation.get("manifest_hash") == checked["manifest_hash"]
                                and bool(checked.get("completion_hash"))
                                and observation.get("completion_hash") == checked["completion_hash"]
                                and isinstance(source, dict) and source.get("schema") == "SITINA_WORKSPACE_CHECK_BINDING_V1"
                                and source.get("task_id") == task["task_id"] and source.get("cwd") == checked.get("cwd")
                                and Path(str(checked.get("cwd"))).resolve() == Path(artifact["workspace_path"]).resolve())
                        else:
                            complete = (complete and isinstance(completion, dict)
                                and completion.get("schema") == "SITINA_LOOP_COMMAND_COMPLETION_OBSERVATION_V1"
                                and completion.get("task_id") == task["task_id"]
                                and completion.get("status") == "COMPLETED"
                                and type(completion.get("exit_code")) is int
                                and completion["exit_code"] == checked["exit_code"]
                                and bool(checked.get("manifest_hash"))
                                and completion.get("manifest_hash") == checked["manifest_hash"]
                                and completion.get("completion_hash") == checked.get("completion_hash"))
                        if complete and checked["exit_code"] == 0 and checked.get("program_status") == "PASS":
                            result["check_status"] = "PASS"
                        elif complete and checked["exit_code"] != 0:
                            result["check_status"] = "FAIL"
        created = events[0].payload if events and events[0].event_type == "loop.task-created" else {}
        required = task.get("required_outcome_ids", created.get("required_outcome_ids"))
        valid_required = (isinstance(required, (list, tuple)) and bool(required)
                          and all(isinstance(item, str) and item for item in required))
        accepted = set()
        for document in acceptances:
            refs = document.get("evidence_refs")
            if (document.get("program_status") == "PASS"
                    and document.get("reviewer_status") == result["review_status"]
                    and result["review_status"] in {"PASS", "NOT_REQUIRED"}
                    and result["check_status"] in {"PASS", "NOT_REQUIRED"}
                    and document.get("delivery_verified") is True
                    and isinstance(refs, list) and task["artifact_ref"] in refs
                    and (result["check_status"] != "PASS" or program_ref in refs)):
                accepted.add(document.get("outcome_id"))
                result["acceptance_ids"].append(document["acceptance_id"])
                references.update(ref for ref in refs if isinstance(ref, str))
        failed = (task.get("status") in {"FAILED", "CANCELLED"}
                  or result["review_status"] == "FAIL" or result["check_status"] == "FAIL")
        if failed:
            result.update(state="failed", reason="当前成果未通过验收，或所属任务已失败／取消。")
        elif (task.get("status") == "SUCCEEDED" and valid_required and set(required) <= accepted
              and task.get("received_input_seq") == task.get("handled_input_seq")
              and not task.get("active_operation_ids") and not task.get("unknown_effect_operation_ids")):
            result.update(state="verified", reason="原生任务验收已完成，当前成果版本与验收记录一致。")
        elif task.get("status") not in TERMINAL:
            result.update(state="in_review", reason="当前成果仍在执行或评审，验收完成前暂不提供下载。")
        result["evidence_ref_count"] = len(references)
        result["evidence_refs"] = sorted(references)[:12]
        result["evidence_refs_more"] = max(0, len(references) - 12)
        return result

    @contextmanager
    def _read_scope(self, sid, operation):
        started = time.monotonic()
        lock = self._lock(sid)
        lock.acquire()
        acquired = time.monotonic()
        observed_host = self._hosts.get(sid)
        host_backend_available = observed_host is not None and observed_host.backend is not None
        last = acquired
        phases = {"lock_wait": acquired - started}
        outcome = "ok"

        def mark(name):
            nonlocal last
            now = time.monotonic()
            phases[name] = now - last
            last = now

        try:
            yield mark
        except BaseException as error:
            outcome = type(error).__name__
            raise
        finally:
            elapsed = time.monotonic() - started
            lock.release()
            if elapsed >= 1:
                try:
                    logging.getLogger(__name__).warning("sitina_web_slow_read %s", json.dumps({
                        "operation": operation, "session_id": sid, "outcome": outcome,
                        "elapsed_seconds": elapsed, "phases_seconds": phases,
                        "host_backend_available_at_lock_acquire": host_backend_available,
                    }, sort_keys=True))
                except Exception:
                    pass  # Diagnostics must never change a read result or its original error.

    def _forget_file_history(self, sid=None):
        with self._guard:
            for key in list(self._file_history):
                if sid is None or key[0] == sid:
                    self._file_history_bytes -= self._file_history.pop(key)["size_bytes"]

    def _cached_file_history(self, key, binding):
        with self._guard:
            cached = self._file_history.get(key)
            if cached is None:
                return None
            if cached["binding"] != binding:
                self._file_history_bytes -= self._file_history.pop(key)["size_bytes"]
                return None
            self._file_history.move_to_end(key)
            return {"source_snapshot": dict(cached["source_snapshot"])
                    if cached["source_snapshot"] is not None else None,
                    "generated": set(cached["generated"])}

    def _remember_file_history(self, key, binding, source_snapshot, generated):
        # Only immutable history-derived paths are retained; current artifact,
        # acceptance, review, program receipts and file bytes are always read again.
        value = {"binding": binding, "source_snapshot": dict(source_snapshot)
                 if source_snapshot is not None else None, "generated": tuple(sorted(generated))}
        size = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
        with self._guard:
            old = self._file_history.pop(key, None)
            if old is not None:
                self._file_history_bytes -= old["size_bytes"]
            if size > MAX_FILE_HISTORY_CACHE_BYTES:
                return
            value["size_bytes"] = size
            self._file_history[key] = value
            self._file_history_bytes += size
            while (len(self._file_history) > MAX_FILE_HISTORY_CACHE_ITEMS
                   or self._file_history_bytes > MAX_FILE_HISTORY_CACHE_BYTES):
                _key, removed = self._file_history.popitem(last=False)
                self._file_history_bytes -= removed["size_bytes"]

    def _file_release_context(self, sid, task_states=None):
        meta = self._meta(sid)
        pending = self._pending_submission_task_ids(sid, meta)
        task_ids = list(dict.fromkeys(item["task_id"] for item in meta["messages"]
                                       if item["task_id"] not in pending))
        context = {"tasks": [], "source_snapshot": None, "has_tasks": bool(task_ids), "versions": {}}
        if not task_ids:
            return context
        host = self._hosts.get(sid)
        try:
            if host is not None and host.backend is not None:
                events_for = host.backend.store.task_events
                def read_document(payload, ref_key, hash_key):
                    return host.backend.context_memory.read(payload[ref_key], expected_hash=payload[hash_key])
            else:
                _runtime, cas, events = read_authenticated_journal(
                    self.directory(sid) / "state", keychain_backend=self.keychain_backend)
                def events_for(task_id):
                    return [event for event in events if event.stream_id == "loop-task/" + task_id]
                def read_document(payload, ref_key, hash_key):
                    return _read_native_document(cas, payload[ref_key], payload[hash_key])
            for index, task_id in enumerate(task_ids):
                task = ((task_states or {}).get(task_id) or self._task(sid, task_id))
                item = {"task": task, "artifact": None, "generated": set(),
                        "release": {"state": "unverified", "reason": "原生验收证据尚不可读。"}}
                context["tasks"].append(item)
                task_events = [event for event in events_for(task_id)
                               if event.stream_version <= task["task_revision"]]
                artifact_events = [event for event in task_events if event.event_type in
                                   {"loop.task-created", "loop.artifact-updated"}]
                history_key = (sid, task_id)
                history_binding = (task["task_revision"], task.get("artifact_ref"), tuple(
                    (event.stream_version, event.event_type, event.payload.get("artifact_ref"),
                     event.payload.get("artifact_hash")) for event in artifact_events))
                history = self._cached_file_history(history_key, history_binding)
                source_snapshot = history["source_snapshot"] if history is not None else None
                history_error = False
                if history is not None:
                    item["generated"].update(history["generated"])
                    if index == 0:
                        context["source_snapshot"] = source_snapshot
                for event in artifact_events:
                    if (history is not None
                            and event.payload.get("artifact_ref") != task.get("artifact_ref")):
                        continue
                    try:
                        document = read_document(event.payload, "artifact_ref", "artifact_hash")
                    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
                        context["evidence_unavailable"] = True
                        history_error = True
                        continue
                    schema = document.get("schema")
                    if schema == "SITINA_LOOP_INITIAL_ARTIFACT_V1" and event.event_type == "loop.task-created":
                        workspace = document.get("workspace")
                        if not isinstance(workspace, dict) or workspace.get("exists") is not True:
                            continue
                        snapshot = workspace.get("content_snapshot")
                        workspace_path = workspace.get("path")
                    elif schema == "SITINA_LOOP_ARTIFACT_V1":
                        snapshot = document.get("workspace_snapshot")
                        workspace_path = document.get("workspace_path")
                    else:
                        continue
                    if (document.get("task_id") != task_id
                            or Path(str(workspace_path)).resolve()
                                != (self.directory(sid) / "workspace").resolve()
                            or not isinstance(snapshot, dict)
                            or any(not isinstance(name, str) or not isinstance(version, str)
                                   or re.fullmatch("[0-9a-f]{64}", version) is None
                                   for name, version in snapshot.items())):
                        continue
                    if event.event_type == "loop.task-created":
                        source_snapshot = snapshot
                        if index == 0:
                            context["source_snapshot"] = snapshot
                    if schema == "SITINA_LOOP_INITIAL_ARTIFACT_V1":
                        continue
                    changed = document.get("changed_paths")
                    if isinstance(changed, list):
                        item["generated"].update(name for name in changed if isinstance(name, str))
                    if event.payload["artifact_ref"] == task.get("artifact_ref"):
                        item["artifact"] = document
                if history_error:
                    self._forget_file_history(sid)
                elif history is None:
                    self._remember_file_history(history_key, history_binding, source_snapshot, item["generated"])
                item["release"] = self._artifact_release(task, item["artifact"], task_events, read_document)
        except (OSError, RuntimeError, ValueError, KeyError, TypeError):
            # Unknown native evidence never grants a download or starts a Host.
            context["evidence_unavailable"] = True
        return context

    def _file_release(self, sid, fid, version, context):
        generated = [item for item in context["tasks"] if fid in item["generated"]]
        baseline = context["source_snapshot"]
        if version and (not context["has_tasks"]
                        or (not generated and isinstance(baseline, dict) and baseline.get(fid) == version)):
            return {"kind": "source", "release_state": "source", "release_reason": "原始来源文件。",
                    "version": version, "downloadable": True, "unverified_available": False}
        owner = generated[-1] if generated else context["tasks"][-1] if context["tasks"] else None
        release = dict(owner["release"]) if owner else {"state": "unverified", "reason": "尚无可核对的原生验收记录。"}
        task = owner["task"] if owner else {}
        artifact = owner["artifact"] if owner else None
        snapshot = artifact.get("workspace_snapshot", {}) if artifact else {}
        if release["state"] == "verified" and fid not in owner["generated"]:
            release.update(state="unverified", reason="该文件尚无本任务成果路径与验收记录的绑定。")
        if release["state"] == "verified":
            if "snapshot_current" not in owner:
                versions = context["versions"]
                current = True
                for name, expected in snapshot.items():
                    if Path(name).is_absolute() or ".." in Path(name).parts:
                        current = False
                        break
                    if name not in versions:
                        versions[name] = self._file_version(self.directory(sid) / "workspace" / name)
                    if versions[name] != expected:
                        current = False
                owner["snapshot_current"] = current
            if not version or snapshot.get(fid) != version or not owner["snapshot_current"]:
                release.update(state="unverified", reason="成果文件在验收后发生变化，需要重新核验当前版本。")
        if task.get("status") in {"FAILED", "CANCELLED"}:
            release.update(state="failed", reason="所属任务已失败／取消；保存的文件尚未通过当前任务验收。")
        state, reason = release.pop("state"), release.pop("reason")
        return {"kind": "generated", "release_state": state,
                "release_reason": reason, "version": version,
                "downloadable": state == "verified",
                "unverified_available": bool(version and task.get("status") in {"FAILED", "CANCELLED"}),
                "task_id": task.get("task_id"), "artifact_ref": task.get("artifact_ref"),
                "artifact_version": task.get("artifact_version"), **release}

    def files(self, sid: str, *, task_states=None):
        context = self._file_release_context(sid, task_states)
        workspace = self.directory(sid) / "workspace"
        result = []
        for parent, dirs, names in os.walk(workspace, followlinks=False):
            dirs[:] = [name for name in dirs if name != "uploads" and not name.startswith(".")
                       and not (Path(parent) / name).is_symlink()]
            for name in sorted(names):
                path = Path(parent) / name
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or name.startswith("."):
                    continue
                relative = str(path.relative_to(workspace))
                version = self._file_version(path)
                context["versions"][relative] = version
                release = self._file_release(sid, relative, version, context)
                if info.st_size > 32 * 1024 * 1024:
                    release.update(downloadable=False, unverified_available=False,
                                   release_reason="文件超出直接下载范围，可在本机会话目录查看。")
                result.append({"id": relative, "name": name, "size": info.st_size, **release})
        return sorted(result, key=lambda item: item["id"])

    def read_file(self, sid: str, fid: str, *, allow_unverified: bool = False,
                  expected_version: str | None = None) -> tuple[bytes, str]:
        with self._read_scope(sid, "read_file") as mark:
            raw, name = self._read_owned_file(sid, fid)
            mark("read_owned_file")
            version = hashlib.sha256(raw).hexdigest()
            if expected_version is not None and expected_version != version:
                raise WebError("文件版本已变化，请刷新后查看当前状态。", status=409, code="file_changed")
            context = self._file_release_context(sid)
            mark("release_context")
            context["versions"][fid] = version
            release = self._file_release(sid, fid, version, context)
            mark("release_current_files")
            if release["downloadable"]:
                return raw, name
            if allow_unverified and release["unverified_available"]:
                if expected_version is None:
                    raise WebError("取回未验证副本需要当前文件版本。", status=409, code="version_required")
                return raw, "UNVERIFIED-" + name
            raise WebError(release["release_reason"], status=409, code="artifact_unverified")

    def _read_owned_file(self, sid: str, fid: str) -> tuple[bytes, str]:
        if not isinstance(fid, str) or not fid or Path(fid).is_absolute() or ".." in Path(fid).parts:
            raise WebError("无效成果路径。", status=400, code="invalid_file")
        with self._lock(sid):
            path = _physical(self.directory(sid) / "workspace" / fid, directory=False)
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 32 * 1024 * 1024:
                raise WebError("成果无法直接下载；可在本机会话目录查看。", code="file_unavailable")
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if ((opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                        or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
                    raise WebError("成果在读取时发生变化。", code="file_changed")
                raw = stream.read(32 * 1024 * 1024 + 1)
                after, current = os.fstat(stream.fileno()), path.lstat()
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")
                if any(getattr(info, field) != getattr(opened, field)
                       or getattr(opened, field) != getattr(after, field)
                       or getattr(after, field) != getattr(current, field) for field in fields):
                    raise WebError("成果在读取时发生变化，请重新取得当前版本。", status=409, code="file_changed")
                if len(raw) > 32 * 1024 * 1024:
                    raise WebError("成果超出直接下载范围。", code="file_unavailable")
                return raw, path.name

    def read_upload(self, sid: str, fid: str) -> tuple[bytes, str]:
        with self._lock(sid):
            meta = self._meta(sid)
            item = next((item for item in meta["uploads"] if item["id"] == fid), None)
            if item is None:
                raise WebError("附件不属于此会话。", status=404, code="not_found")
            raw, _name = self._read_owned_file(sid, "uploads/" + item["stored_name"])
            if hashlib.sha256(raw).hexdigest() != item.get("sha256"):
                raise WebError("来源附件已发生变化，不能将当前字节作为原始附件下载。", status=409, code="attachment_changed")
            return raw, item["name"]

    def context_activity(self, sid: str):
        # Do not acquire the native task projection lock: preparation holds it
        # while compacting. This endpoint is only a live UI observation.
        from sitina.loop.activity import read_context_activity
        meta = self._meta(sid)
        task_id = meta["messages"][-1]["task_id"] if meta["messages"] else None
        activity = read_context_activity(self.directory(sid) / "state", task_id)
        return {"task_id":task_id, **activity}

    def snapshot(self, sid: str):
        with self._read_scope(sid, "snapshot") as mark:
            meta = self._meta(sid)
            # Reconcile explicit pending intents; this is only local metadata,
            # never a second control send or a business task.
            self._reconcile(sid, meta, persist=False)
            mark("reconcile")
            tasks, messages, past_responses = {}, [], {}
            errors = []
            pending_submissions = self._pending_submission_task_ids(sid, meta)
            first_messages, last_messages = {}, {}
            for item in meta["messages"]:
                first_messages.setdefault(item["task_id"], item["id"])
                last_messages[item["task_id"]] = item["id"]
            for item in meta["messages"]:
                task_id = item["task_id"]
                if task_id not in tasks and task_id not in pending_submissions:
                    try:
                        tasks[task_id] = self._task(sid, task_id)
                        for response in self._past_responses(sid, tasks[task_id], last_messages[task_id]):
                            reply_to = response["reply_to"] or first_messages[task_id]
                            past_responses[reply_to] = response
                    except (RuntimeError, OSError, ValueError, KeyError) as error:
                        errors.append({"task_id": task_id, "reason": redact_text(str(error))})
                messages.append(item)
                if (sid, item["id"]) in self._inflight_dispatches:
                    continue
                if item["id"] != last_messages[task_id]:
                    response = past_responses.get(item["id"])
                    if response:
                        messages.append({**response, "role": "assistant", "text": response.get("text", ""),
                                         "runtime_notice": _task_notice(response),
                                         "task_id": task_id, "reply_to": item["id"],
                                         "historical": True, "animating": False})
                else:
                    task = tasks.get(task_id)
                    if task:
                        final = (task.get("terminal_result") or {}).get("final_result") or {}
                        response = final.get("response") if isinstance(final, dict) else None
                        verification = self._verification_view(sid, task)
                        messages.append({"id": "answer-" + task_id, "role": "assistant",
                                         "text": str(response or ""), "task_id": task_id,
                                         "runtime_notice": _task_notice(task),
                                         "verification_activity": verification,
                                         "work_plan": task.get("work_plan"),
                                         "activity": activity_summary(task, self._activity_view(sid, task)),
                                         "reply_to": item["id"],
                                         "status": task["status"], "at": (past_responses.get(item["id"]) or {}).get("at")
                                         or verification["notice_at"],
                                         "animating": sid in self._hosts and task["control_intent"] == "RUN"
                                         and task["status"] in {"RUNNABLE", "WAITING_OPERATION", "WAITING_CHILD"}})
            latest = tasks.get(meta["messages"][-1]["task_id"]) if meta["messages"] else None
            mark("tasks")
            if latest:
                total_rounds, activity, recorded_reviewers = _agent_activity(latest)
                native_counts = latest.get("team_counts")
                if not isinstance(native_counts, dict):
                    native_counts = None  # Cold schemas can omit a live-only field.
                agents = [{"id": latest["task_id"], "role": "main", "name": "主 Agent",
                           "objective": (latest.get("goal_summary") or {}).get("objective") or next(
                               (m["text"] for m in meta["messages"]
                                if m["task_id"] == latest["task_id"] and m.get("starts_task")), meta["title"]),
                           "status": "WAITING" if native_counts and native_counts["main"]["waiting"]
                           else latest["status"], "reason": "协调当前任务并汇总成果"}]
                for child_id, child in latest.get("child_delegations", {}).items():
                    agents.append({"id": child_id, "role": "child", "name": child.get("role") or "子 Agent",
                                   "objective": child.get("objective") or "",
                                   "status": child.get("status") or "UNKNOWN",
                                   "reason": child.get("change_reason") or child.get("cancel_reason") or "",
                                   "handoff_from": child.get("handoff_from"),
                                   "replacement_for": child.get("replacement_for")})
                host = self._hosts.get(sid)
                if host and native_counts and native_counts["reviewer"]["created"]:
                    projection = host.backend.get_task(latest["task_id"])
                    review_operations = [op for op in projection.operations.values()
                        if op.agent_role == "reviewer" and (op.business_attempt_id or op.agent_instance_id)]
                    reviewer_ids = sorted({op.business_attempt_id or op.agent_instance_id for op in review_operations})
                    active_ids = {op.operation_id for op in projection.active_operations}
                    open_attempts = set(projection.attempt_plans) - {
                        str(item.get("attempt_id")) for item in projection.attempt_settlements
                        if item.get("termination_contract_version") == "sitina-termination-v1"}
                    for ordinal, reviewer_id in enumerate(reviewer_ids, 1):
                        active = not projection.is_terminal and any(
                            op.operation_id in active_ids or op.business_attempt_id in open_attempts
                            for op in review_operations
                            if (op.business_attempt_id or op.agent_instance_id) == reviewer_id)
                        agents.append({"id": reviewer_id, "role": "reviewer", "name": f"评审批次 · {ordinal}",
                            "objective": "核对当前任务成果",
                            "status": "WAITING" if active and native_counts["reviewer"]["waiting"]
                            else "RUNNING" if active else "ENDED", "reason": "本任务累计评审记录"})
                else:
                    for ordinal, reviewer_id in enumerate(recorded_reviewers, 1):
                        agents.append({"id": reviewer_id, "role": "reviewer", "name": f"评审批次 · {ordinal}",
                            "objective": "核对当前任务成果",
                            "status": "ENDED" if latest["status"] in TERMINAL else "UNKNOWN",
                            "reason": "本任务累计评审记录"})
                data_flows = _agent_data_flow(latest)
                for agent in agents:
                    agent.update(activity.get(agent["id"], {"interaction_rounds": None, "skills": None}))
                    agent["data_flow"] = data_flows.get(agent["id"])
                telemetry = latest.get("agent_telemetry")
                usage = telemetry.get("totals") if isinstance(telemetry, dict) else None
                task_view = {key: latest.get(key) for key in
                             ("task_id", "status", "task_revision", "waiting_reason", "work_plan",
                              "unknown_effect_operation_ids", "active_operation_ids", "control_intent",
                              "goal_summary", "recovery_state")}
                task_view["verification_activity"] = self._verification_view(sid, latest)
                task_view["activity"] = activity_summary(latest, self._activity_view(sid, latest))
                task_view["runtime_notice"] = _task_notice(latest)
                task_view["context_usage"] = _task_context_usage(latest)
                provider = (
                    host.backend.provider_response_preview(latest["task_id"], host.descriptor_context)
                    if host is not None else
                    {"state": "unavailable", "reason": "连接原任务后才能核对缺失回复，尚未获得继续许可。"}
                    if latest.get("unknown_effect_operation_ids") else None
                )
                task_view["provider_response_recovery"] = provider
                task_view["software_update"] = (
                    host.backend.software_update_preview(latest["task_id"], host.descriptor_context)
                    if host is not None and provider is None else None
                )
            else:
                agents, native_counts, usage, task_view = [], None, None, None
                total_rounds = None
            mark("task_view")
            file_list = self.files(sid, task_states=tasks)
            mark("files")
            from sitina.cli import _loop_usage_line
            return {"session": self.summary(meta), "directory": str(self.directory(sid)),
                    "messages": messages, "task": task_view,
                    "agents": agents, "team_counts": native_counts, "usage": usage,
                    "interaction_rounds": total_rounds,
                    "usage_text": _loop_usage_line(latest) if latest else "",
                    "model": ModelSelectionStore(self.directory(sid) / "state").read(),
                    "files": file_list, "uploads": [
                        {key: item[key] for key in ("id", "name", "size")} for item in meta["uploads"]],
                    "connected": sid in self._hosts, "status_errors": errors,
                    "pending_actions": [a for a in meta["actions"].values()
                                        if a["state"] in {"PENDING", "OUTCOME_UNKNOWN", "NOT_SENT"}]}

    def open_folder(self, sid: str):
        with self._lock(sid):
            path = self.directory(sid)
            result = subprocess.run(["/usr/bin/open", str(path)], capture_output=True, timeout=10, check=False)
            if result.returncode:
                raise WebError("系统无法打开文件夹；目录路径仍可复制。", code="open_failed")
            return {"status": "opened"}

    def delete(self, sid: str, confirmation: str, *, drain_timeout: float = 12):
        with self._command_lock(sid):
            return self._delete(sid, confirmation, drain_timeout=drain_timeout)

    def _delete(self, sid: str, confirmation: str, *, drain_timeout: float = 12):
        if confirmation != sid:
            raise WebError("请确认将要删除的具体会话。", status=400, code="confirmation_required")
        with self._lock(sid):
            if self._deletion_observation(sid)["confirmation"] == "REMOVED":
                return {"status":"deleted", "id":sid, "directory_removed":True,
                        "external_files_deleted":False}
            meta = self._meta(sid)
            path = self.directory(sid)
            meta["deleting"] = True
            self._forget_file_history(sid)
            self._save(sid, meta)  # Durable admission/upload/model fence.
            try:
                host = self._hosts.get(sid)
                cleaning = meta.get("deletion_phase") == "CLEANING"
                if cleaning and host is not None:
                    raise WebError("清理阶段仍有原生 Host，已停止删除。", code="host_not_closed")
                if not cleaning:
                    self._reconcile(sid, meta)
                    if any(a["state"] in {"PENDING", "OUTCOME_UNKNOWN"} for a in meta["actions"].values()):
                        raise WebError("前一次操作结果尚未确认；保留原始记录，未开始清理。", code="outcome_unknown")
                if host and not cleaning:
                    # Include every native task, including associated children.
                    task_ids = list(host.backend.task_ids())
                    for task_id in task_ids:
                        task = host.backend.get_task(task_id)
                        if not task.is_terminal:
                            cancel_id = "delete-" + hashlib.sha256((sid + task_id).encode()).hexdigest()[:32]
                            if input_receipt(task, cancel_id).get("status") != "RECEIVED":
                                response = send_control_input(path / "state", {
                                    "command": "input", "task_id": task_id, "input_id": cancel_id,
                                    "kind": "CANCEL", "body": "用户确认彻底删除此网页会话。"})
                                if response.get("delivery_status") != "ACCEPTED":
                                    raise WebError("取消回执未确认；记录已保留，未开始清理。", code="cancel_unconfirmed")
                    if not host.wait_for_quiescence(drain_timeout):
                        raise WebError("仍有 Agent 或后台操作正在收口。会话已停止新写入，尚未删除；稍后核对。", code="still_draining")
                    # Include children admitted while cancellation was draining.
                    for task_id in host.backend.task_ids():
                        self._require_settled(host.backend.get_task(task_id).as_dict())
                    host.close()
                    if host.backend is not None or host.control is not None or host.lease is not None:
                        raise WebError("原生 Host 尚未完全关闭，未开始删除。", code="host_not_closed")
                    del self._hosts[sid]
                state = path / "state"
                with LoopAuthorityLease(state):
                    _physical(path)
                    if not cleaning and (state / ".sitina-session-runtime-v1").exists():
                        self._cancel_cold(sid, state)
                    fence = path / ".web-deletion-fence.json"
                    expected_fence = {"schema": "SITINA_WEB_DELETION_FENCE_V1", "session_id": sid}
                    if cleaning:
                        if _json(fence) != expected_fence:
                            raise WebError("删除阶段的停止边界无法核实。", code="unsafe_deletion")
                    else:
                        _write(fence, expected_fence)
                        meta["deletion_phase"] = "CLEANING"
                        meta["delete_error"] = None
                        self._save(sid, meta)
                    # The native endpoint is derived from this exact state
                    # root. Only its empty, closed directory is removable.
                    endpoint = authority_socket_path(state)
                    if endpoint.exists() or endpoint.is_symlink():
                        raise WebError("原生控制端点仍存在，未开始清理。", code="control_endpoint_present")
                    if endpoint.parent.exists():
                        # The native socket contract uses /tmp, which is an
                        # OS-provided alias on macOS. Resolve that base only;
                        # the individually derived endpoint must be physical.
                        endpoint_directory = _physical(
                            endpoint.parent.parent.resolve(strict=True) / endpoint.parent.name)
                        if endpoint_directory.stat().st_uid != os.getuid():
                            raise WebError("控制端点目录归属异常。", code="unsafe_deletion")
                        endpoint_directory.rmdir()
                    if (state / ".sitina-session-runtime-v1").exists():
                        namespace = LoopRuntimeContext._namespace(state)
                        provider = MacOSKeychainProvider(environment="sitina-loop", namespace=namespace,
                            **({"backend": self.keychain_backend} if self.keychain_backend is not None else {}))
                        provider.destroy_namespace()
                    # Keep only an irreversible ID reservation, containing no
                    # chat, path, attachment, task, logs, credential or result.
                    tombstone = self.root / (".deleted-" + sid)
                    if not tombstone.exists():
                        fd = os.open(tombstone, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                        os.close(fd)
                    info = tombstone.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_size != 0 or info.st_uid != os.getuid():
                        raise WebError("会话删除身份异常。", code="unsafe_tombstone")
                    # Keep the ownership and error record until every data
                    # subtree has been removed. rmtree never follows links.
                    retained = {"session.json", ".web-session-owner.json", ".web-deletion-fence.json"}
                    for child in sorted(path.iterdir()):
                        if child.name in retained:
                            continue
                        if stat.S_ISDIR(child.lstat().st_mode):
                            shutil.rmtree(child)
                        else:
                            child.unlink()
                    (path / ".web-session-owner.json").unlink()
                    fence.unlink()
                    (path / "session.json").unlink()
                    path.rmdir()
                if path.exists() or path.is_symlink():
                    raise WebError("目录清理未全部完成。", code="partial_delete")
                return {"status": "deleted", "id": sid, "directory_removed": True,
                        "external_files_deleted": False}
            except Exception as error:
                if (path / "session.json").is_file():
                    meta["delete_error"] = redact_text(str(error))
                    try:
                        self._save(sid, meta)
                    except (WebError, OSError):
                        pass  # list() still exposes an incomplete directory.
                if isinstance(error, WebError):
                    raise
                if isinstance(error, LoopAuthorityError):
                    raise WebError("会话仍被另一个原生进程占用，未删除；请先结束该会话的运行。",
                                   code="authority_busy") from error
                raise WebError("删除未全部完成，已保留剩余现场：" + redact_text(str(error)),
                               code="partial_delete") from error

    def _cancel_with_reconciliation(self, sid: str, request_id: str, choice):
        """Preview/accept an explicit cancel-only choice under the native lease.

        This never starts a Host, scheduler, Provider, child or business tool.
        A caller must already have submitted CANCEL; null means preview only.
        """
        with self._lock(sid):
            meta = self._meta(sid)
            if self._closed or meta.get('deletion_phase') == 'CLEANING':
                raise WebError('服务停止或文件清理过程中不能核对取消。', code='cancel_reconciliation_unavailable')
            # A failed deletion keeps the admission fence set. Cancelling its
            # task is allowed under the same command lock, without clearing
            # that fence or starting/removing any business files.
            if sid in self._hosts:
                raise WebError('会话仍连接执行进程，请先等待其安全停止；没有重发任何操作。',
                               code='cancel_host_still_connected')
            task_id = next((message['task_id'] for message in reversed(meta['messages'])
                            if message.get('task_id')), None)
            if not task_id:
                raise WebError('此会话没有可核对的原生任务。', code='no_task')
            path = self.directory(sid)
            state = path / 'state'
            with LoopAuthorityLease(state):
                _physical(path)
                args = SimpleNamespace(state_root=str(state), workspace=str(path / 'workspace'),
                                       provider_profile='deepseek', resource_policy=None,
                                       observability_policy=None)
                native, _boundary = self.factory(args)
                backend = None
                try:
                    kwargs = {'keychain_backend': self.keychain_backend} if self.keychain_backend is not None else {}
                    backend = native.backend_factory(state, **kwargs)
                    task = backend.get_task(task_id)
                    if choice is None:
                        return backend.cancel_reconciliation_preview(task_id, native.descriptor_context)
                    if not isinstance(choice, dict):
                        raise WebError('取消核对需要完整确认记录。', status=400, code='invalid_control')
                    task = backend.request_cancel_reconciliation(
                        task_id, request_id=request_id, request=choice,
                        host_descriptor_context=native.descriptor_context,
                    )
                    if not task.is_terminal:
                        task = RecoveryCoordinator(backend, descriptor_validator=native.recovery_validator).recover(task_id)
                        task = backend.cancel_safely(task_id)
                    self._require_settled(task.as_dict())
                    return {'status': 'CANCELLED', 'task_id': task_id,
                            'task_revision': task.task_revision, 'request_id': request_id,
                            'reconciliation': task.cancel_reconciliation,
                            'original_usage_unsettled': task.cancel_reconciliation['usage_unsettled'],
                            'business_replayed': False, 'files_deleted': False}
                finally:
                    if backend is not None:
                        backend.close()
                    native.close()

    def _cancel_cold(self, sid: str, state: Path):
        """Use native cancellation/recovery without starting any worker.

        The caller owns the native authority lease. No task Runner, child
        executor, Provider or publication worker is started on this path.
        """
        path = self.directory(sid)
        args = SimpleNamespace(state_root=str(state), workspace=str(path / "workspace"),
                               provider_profile="deepseek", resource_policy=None,
                               observability_policy=None)
        native, _boundary = self.factory(args)
        kwargs = {"keychain_backend": self.keychain_backend} if self.keychain_backend is not None else {}
        backend = native.backend_factory(state, **kwargs)
        try:
            recovery = RecoveryCoordinator(backend, descriptor_validator=native.recovery_validator)
            for task_id in backend.task_ids():
                task = backend.get_task(task_id)
                if not task.is_terminal:
                    if task.active_operations or task.unresolved_effects:
                        raise TaskConflict("仍有执行中或结果未知的操作，未删除；请先核对原操作结果。")
                    children = task.as_dict().get("child_delegations", {})
                    if any(child.get("unknown_effect") or child.get("status") in
                           {"RUNNING", "CANCEL_REQUESTED", "DISPATCH_PENDING"}
                           for child in children.values()):
                        raise TaskConflict("子任务尚未安全收口，未删除；原任务和成果已保留。")
                    cancel_id = "delete-" + hashlib.sha256((sid + task_id).encode()).hexdigest()[:32]
                    if input_receipt(task, cancel_id).get("status") != "RECEIVED":
                        backend.accept_input(task_id, input_id=cancel_id, kind=InputKind.CANCEL,
                                             body="用户确认彻底删除此网页会话。")
                    # Deletion authorizes cancellation, never renewed execution.
                    # Bind a source-only transition through the same authenticated
                    # cancellation contract used by the ordinary cold cancel path.
                    task = backend.get_task(task_id)
                    if task.cancel_reconciliation is None:
                        preview = backend.cancel_reconciliation_preview(task_id, native.descriptor_context)
                        choice = preview.get("request")
                        if (preview.get("state") != "confirmation_required"
                                or preview.get("original_usage_unsettled") is not False
                                or not isinstance(choice, dict) or choice.get("operation_id") is not None
                                or choice.get("accept_unknown_usage") is not False
                                or choice.get("abandon_missing_response") is not False):
                            raise TaskConflict("删除前的取消核对尚未通过；原任务和成果已保留。")
                        backend.request_cancel_reconciliation(
                            task_id, request_id=cancel_id + ":settle",
                            request={**choice, "confirm_cancel": True},
                            host_descriptor_context=native.descriptor_context)
                    recovery.recover(task_id)
                    task = backend.cancel_safely(task_id)
                self._require_settled(task.as_dict())
        finally:
            backend.close()
            native.close()

    @staticmethod
    def _require_settled(task: dict[str, Any]):
        children = task.get("child_delegations", {})
        unresolved = any(child.get("unknown_effect") or child.get("status") in
                         {"RUNNING", "CANCEL_REQUESTED", "DISPATCH_PENDING"} for child in children.values())
        reasons = []
        if task["status"] not in TERMINAL:
            reasons.append("任务尚未结束" if task["status"] != "RECOVERY_BLOCKED" else "任务恢复待核对")
        if task.get("unknown_effect_operation_ids"):
            reasons.append("外部动作结果未知")
        if task.get("active_operation_ids"):
            reasons.append("操作仍在执行")
        if task.get("owned_resources"):
            reasons.append("任务资源尚未释放")
        if unresolved:
            reasons.append("子任务尚未收口")
        if reasons:
            raise WebError("未删除：" + "；".join(reasons) + "。不会重发原业务，请先核对会话状态。", code="unsettled")

    def close(self, timeout: float = 15, *, preserve_running: bool = False, handoff_current=None) -> bool:
        """Pause and drain; an explicit planned handoff preserves authorized original work."""
        self._closed = True
        self._forget_file_history()
        complete = self.deletion_queue.close(timeout)
        for sid, host in list(self._hosts.items()):
            command_lock = self._command_lock(sid)
            if not command_lock.acquire(timeout=max(0, timeout)):
                complete = False
                continue
            try:
                with self._lock(sid):
                    for task_id in host.backend.task_ids():
                        task = host.backend.get_task(task_id)
                        if not task.is_terminal and task.control_intent.value != "PAUSE":
                            send_control_input(self.directory(sid) / "state", {
                                "command": "input", "task_id": task_id,
                                "input_id": "shutdown-" + secrets.token_hex(16), "kind": "PAUSE", "body": ""})
                    if host.wait_for_quiescence(timeout):
                        if preserve_running:
                            host.close(preserve_running=True, handoff_current=handoff_current)
                        else:
                            host.close()
                        if host.backend is None:
                            del self._hosts[sid]
                        else:
                            complete = False
                    else:
                        complete = False
            finally:
                command_lock.release()
        with self._guard:
            if self._inflight_dispatches:
                complete = False
            if self._skills_mutations:
                complete = False
            elif complete and self._skills_backend is not None:
                self._skills_backend.close()
                self._skills_backend = None
                self._skills_service = None
                if self._skills_lease is not None:
                    self._skills_lease.__exit__(None, None, None)
                    self._skills_lease = None
        if complete and self._lease is not None:
            fcntl.flock(self._lease, fcntl.LOCK_UN)
            os.close(self._lease)
            self._lease = None
        return complete
