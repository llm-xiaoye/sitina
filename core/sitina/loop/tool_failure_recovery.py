"""Read-only retry decisions from authenticated, current-input operation receipts.

This is a dispatch boundary, not an acceptance rule. Server text is never
interpreted as proof that a shared initialization phase failed.
"""
import hashlib
import json
import threading
import weakref
from collections.abc import Mapping
from contextlib import contextmanager

MAX_IDENTICAL_FAILURES = 3
_locks = weakref.WeakKeyDictionary()
_lock_guard = threading.Lock()


@contextmanager
def mcp_retry_serialization(backend, task_id, identity):
    """Serialize check plus dispatch for one task/server, including child actors."""
    if identity is None:
        yield
        return
    with _lock_guard:
        task_locks = _locks.setdefault(backend, {})
        lock = task_locks.setdefault((task_id, identity["server"]), threading.RLock())
    with lock:
        yield


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def mcp_retry_identity(plan, tool, arguments):
    contract = plan["method_contract"]
    if contract["controlled_executor"] != "loop-mcp-client":
        raise ValueError("retry identity requires a bound MCP executor")
    server = {key: plan[key] for key in ("snapshot_id", "snapshot_hash", "candidate_id", "root")}
    server.update({key: contract[key] for key in ("server", "transport", "configuration_hash")})
    return {"schema": "SITINA_MCP_RETRY_IDENTITY_V1", "server": _digest(server),
            "request": _digest({"tool": tool, "arguments": arguments})}


def mcp_dispatch_blocker(backend, task, identity):
    """Return provenance for a blocked dispatch, or None. Never dispatch here.

All scopes/actors in the same task share the durable failure history. A new
handled user-input frontier or a different bound configuration gets its own
history. Rejected dispatches do not count as additional physical attempts.
"""
    if task.unresolved_effects:
        return {"kind": "unknown_effect", "automatic_retry": False,
                "evidence_refs": [str(item.result_ref) for item in task.unresolved_effects if item.result_ref],
                "reason": "任务仍有结果未知的操作。先核对实际结果，不能以新请求、配置变化或重试清除这项责任。"}
    matched = []
    error_digest = None
    request_closed = False
    initialization_closed = False
    for operation in reversed(tuple(task.operations.values())):
        # Artifact/acceptance revisions do not repair an unchanged MCP server.
        # Task membership, handled input and bound server/request identities
        # define retry applicability independently of the acceptance lifecycle.
        if operation.bound_input_seq != task.handled_input_seq:
            continue
        if not operation.result_ref:
            continue
        document = backend.context_memory.read(str(operation.result_ref))
        if not isinstance(document, Mapping):
            continue
        result = document.get("result")
        if not isinstance(result, Mapping):
            continue
        recorded = result.get("retry_identity")
        if not isinstance(recorded, Mapping) or recorded.get("schema") != identity["schema"]:
            continue
        if recorded.get("server") != identity["server"]:
            continue
        if result.get("retry_dispatch_blocked") is True:
            continue
        failure = result.get("failure_context")
        if (not initialization_closed and operation.effect_status.value == "FAILED" and result.get("status") == "error"
                and failure == {"schema": "SITINA_MCP_FAILURE_CONTEXT_V1",
                                "phase": "session_initialization", "business_method_sent": False,
                                "shared_initialization_failed": True}
                and isinstance(failure, Mapping)
                and type(failure["business_method_sent"]) is bool
                and type(failure["shared_initialization_failed"]) is bool):
            return {"kind": "shared_initialization", "evidence_refs": [str(operation.result_ref)],
                    "automatic_retry": False, "configuration_identity": identity["server"],
                    "reason": "该 MCP 会话初始化失败，执行端确认尚未发送业务方法。已暂停此配置的自动调用；其他能力不受此规则影响。配置或用户输入发生变化后可重新核对。"}
        if operation.effect_status.value == "SUCCEEDED":
            # A later successful call proves that this server initialized.
            # Exact-request successes also reset its consecutive error history.
            if recorded.get("request") == identity["request"]:
                return None
            initialization_closed = True
            continue
        if request_closed or recorded.get("request") != identity["request"]:
            continue
        if operation.effect_status.value != "FAILED" or result.get("status") != "error":
            request_closed = True
            continue
        digest = _digest(result.get("value"))
        if error_digest is not None and digest != error_digest:
            request_closed = True
            continue
        error_digest = digest
        matched.append(str(operation.result_ref))
        if len(matched) == MAX_IDENTICAL_FAILURES:
            return {"kind": "identical_failures", "evidence_refs": matched,
                    "automatic_retry": False, "configuration_identity": identity["server"],
                    "reason": "相同 MCP 请求在相同配置下连续返回相同错误，已达到 3 次自动尝试上限。已停止该动作，保留原始回执；请先核对原因，条件变化或明确重试后再继续。"}
    return None


def current_mcp_initialization_blocks(backend, task):
    """Current authenticated dispatch restrictions, not proof of task failure.

    The completion consumer must separately identify an unmet requirement that
    needs this capability. A remote error string never enters this inventory.
    """
    identities = {}
    for operation in reversed(tuple(task.operations.values())):
        if operation.bound_input_seq != task.handled_input_seq or not operation.result_ref:
            continue
        document = backend.context_memory.read(str(operation.result_ref))
        result = document.get("result") if isinstance(document, Mapping) else None
        identity = result.get("retry_identity") if isinstance(result, Mapping) else None
        if not isinstance(identity, Mapping) or identity.get("schema") != "SITINA_MCP_RETRY_IDENTITY_V1":
            continue
        if not isinstance(identity.get("server"), str) or not isinstance(identity.get("request"), str):
            continue
        identities.setdefault(identity["server"], (identity, result.get("tool")))
    blocks = []
    for identity, tool in identities.values():
        blocker = mcp_dispatch_blocker(backend, task, identity)
        if blocker is not None and blocker["kind"] == "shared_initialization":
            blocks.append({**blocker, "tool": tool})
    return blocks
