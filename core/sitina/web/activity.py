"""Small public activity views derived from authenticated operation records."""
from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from sitina.security.redaction import redact_text


TOOL_LABELS = {
    "sitina_list_directory": "查看目录", "sitina_read_file": "读取文件",
    "sitina_write_file": "写入文件", "sitina_edit_file": "修改文件",
    "sitina_shell": "运行命令", "sitina_exec": "运行程序",
    "sitina_history_query": "读取任务记录", "sitina_task_skills": "查看技能",
    "sitina_read_skill_resource": "读取技能说明", "sitina_process_start": "启动命令",
    "sitina_process_stop": "停止命令", "sitina_process_status": "查看命令状态",
    "sitina_process_output": "读取命令输出", "sitina_register_service": "登记预览服务",
}
BROWSER_LABELS = {
    "browser_navigate": "打开网页", "browser_snapshot": "读取页面结构",
    "browser_take_screenshot": "截取网页", "browser_evaluate": "检查网页",
    "browser_run_code": "检查网页布局", "browser_resize": "调整浏览器尺寸",
    "browser_tabs": "管理检查标签页", "browser_close": "结束浏览器检查",
    "browser_console_messages": "检查浏览器控制台", "browser_click": "点击网页",
}


def _short(value, limit=220):
    return redact_text(value).replace("\x00", "")[:limit] if isinstance(value, str) else ""


def _tool_view(tool, arguments):
    args = arguments if isinstance(arguments, dict) else {}
    title, category, detail = TOOL_LABELS.get(tool, "调用工具"), "tool", ""
    if tool in {"sitina_task_skills", "sitina_read_skill_resource"}:
        category = "skill"
        title = "加载技能" if args.get("action") == "load" else title
        detail = _short(args.get("name") or args.get("skill"))
        if tool == "sitina_read_skill_resource" and isinstance(args.get("path"), str):
            detail += " / " + _short(args["path"])
    elif tool in {"sitina_read_file", "sitina_write_file", "sitina_edit_file", "sitina_list_directory"}:
        category = "file"
        detail = _short(args.get("path") or args.get("file_path"))
    elif tool in {"sitina_shell", "sitina_exec", "sitina_process_start", "sitina_process_stop", "sitina_process_status", "sitina_process_output"}:
        category = "command"
        argv = args.get("argv") or args.get("command")
        if isinstance(argv, list) and all(isinstance(part, str) for part in argv):
            executable = args.get("executable")
            prefix = executable + " " if isinstance(executable, str) and executable else ""
            detail = _short(prefix + " ".join(argv))
        elif isinstance(argv, str):
            detail = _short(argv)
        else:
            detail = _short(args.get("process_id"))
    elif isinstance(tool, str) and tool.endswith("_call"):
        category = "mcp"
        name = args.get("tool") or args.get("name")
        nested = args.get("arguments")
        nested = nested if isinstance(nested, dict) else {}
        if isinstance(name, str) and name.startswith("browser_"):
            category = "browser"
            title = BROWSER_LABELS.get(name, "操作浏览器")
            url = nested.get("url")
            if isinstance(url, str):
                parsed = urlsplit(url)
                if parsed.scheme in {"http", "https"}:
                    detail = _short(urlunsplit((parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", "")))
        else:
            title, detail = "调用 MCP", _short(name)
    return title, category, detail or ("" if tool in TOOL_LABELS else _short(tool))


def _error_detail(doc, result):
    """Expose only a bounded, redacted error explanation, never success output."""
    error = doc.get("error")
    if isinstance(error, dict):
        error = error.get("message") or error.get("reason") or error.get("code")
    if isinstance(error, str) and error:
        return _short(error, 500)
    if not isinstance(result, dict):
        return ""
    value = result.get("value")
    if not isinstance(value, dict):
        return ""
    if result.get("status") not in {"error", "failed"} and value.get("isError") is not True:
        return ""
    for key in ("message", "reason", "error"):
        if isinstance(value.get(key), str) and value[key]:
            return _short(value[key], 500)
    content = value.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                return _short(item["text"], 500)
    return ""


def _activity_problem_notice(task, entries):
    if task.get("status") in {"SUCCEEDED", "CANCELLED"}:
        return None
    problems = [entry for entry in entries if entry["status"] in {"failed", "unknown"}]
    if not problems:
        return None
    last = problems[-1]
    title = _short(last["title"], 80)
    detail = _short(last.get("error_detail"), 500)
    if last["status"] == "unknown":
        return f"运行提示：{title}的结果尚未确认。已有记录保留，请先核对实际结果，不要重复提交该操作。你可以在输入框继续补充信息。"
    count = sum(1 for entry in problems if entry["status"] == "failed" and detail
                and entry.get("error_detail") == last.get("error_detail"))
    repeated = f"同一错误已记录 {count} 次。" if count > 1 else ""
    state = ("任务仍在继续处理，这条提示不代表整项任务已经失败。"
             if task.get("status") in {"RUNNABLE", "WAITING_OPERATION", "WAITING_CHILD"}
             else "请结合当前任务状态查看后续处理。")
    return (f"运行提示：本轮“{title}”出现异常。" + ("原因：" + detail if detail else "请展开执行记录查看具体回执。")
            + "\n" + repeated + state + "已有记录和成果保留，你可以在输入框继续说明要求。")


def operation_activities(task, events, read_document):
    """No reasoning, source bodies or success output; failures have bounded details."""
    entries = {}
    for event in events:
        payload = event.payload
        if payload.get("task_id") != task["task_id"]:
            continue
        kind = event.event_type
        if kind == "loop.operation-intent-recorded":
            doc = read_document(payload, "intent_ref", "intent_hash")
            if doc.get("task_id") != task["task_id"] or doc.get("operation_id") != payload.get("operation_id"):
                raise ValueError("Activity intent identity differs")
            description = doc.get("description", "")
            # Internal pin/receipt bookkeeping is not another user action.
            if description in {"pin authenticated global Skill versions for this task",
                               "bind an actual tool reply to its authenticated operation result"}:
                continue
            title, category, detail = "执行操作", "tool", ""
            if description.startswith("Provider "):
                category = "model"
                title = "等待模型回复"
                if "goal_interpretation" in description:
                    title = "理解任务要求"
                elif "goal_completion" in description:
                    title, detail = "核对成果与证据", "主 Agent 正在核对完成条件；必要时会继续读取来源。"
                elif "review" in description:
                    title, detail = "独立评审成果", "评审 Agent 正在检查成果与证据。"
            elif description.startswith("execute tool "):
                title, category, detail = _tool_view(description[len("execute tool "):], {})
            elif description == "inspect or select this task's pinned Skills":
                title, category = "查看或加载技能", "skill"
            elif description == "execute a task-authorized program or non-login Shell":
                title, category = "启动命令", "command"
            elif description == "observe or control the original task execution":
                title, category = "管理命令或预览服务", "command"
            entries[payload["operation_id"]] = {
                "id": payload["operation_id"], "order": event.position,
                "title": title, "category": category, "detail": detail,
                "status": "running", "actor": _short(doc.get("agent_role"), 40),
            }
        elif kind == "loop.operation-result-recorded" and payload.get("operation_id") in entries:
            entry = entries[payload["operation_id"]]
            doc = read_document(payload, "result_ref", "result_hash")
            if doc.get("task_id") != task["task_id"] or doc.get("operation_id") != entry["id"]:
                raise ValueError("Activity result identity differs")
            state = doc.get("effect_status")
            entry["status"] = {"SUCCEEDED": "done", "FAILED": "failed", "CANCELLED": "cancelled",
                               "PRECONDITION_CHANGED": "cancelled", "UNKNOWN": "unknown"}.get(state, "unknown")
            if entry["title"] == "等待模型回复" and entry["status"] == "done":
                entry["title"] = "模型回复已收到"
            elif entry["title"] in {"核对成果与证据", "独立评审成果"}:
                if entry["status"] == "done":
                    entry["detail"] = "本次核验请求已返回；最终结论以任务状态和核验记录为准。"
                elif entry["status"] != "running":
                    entry["detail"] = "本次核验请求未正常完成；请查看任务状态与具体原因。"
            result = doc.get("result")
            if entry["status"] in {"failed", "unknown"}:
                entry["error_detail"] = _error_detail(doc, result)
            if not isinstance(result, dict):
                continue
            tool = result.get("tool")
            if isinstance(tool, str):
                binding = result.get("invocation_binding")
                args = binding.get("arguments") if isinstance(binding, dict) else result.get("arguments")
                entry["title"], entry["category"], entry["detail"] = _tool_view(tool, args)
                value = result.get("value")
                if result.get("status") in {"error", "failed"} or (isinstance(value, dict) and value.get("isError") is True):
                    entry["status"] = "failed"
                    entry["error_detail"] = _error_detail(doc, result)
                if tool in {"sitina_shell", "sitina_exec", "sitina_process_start"}:
                    exit_code = result.get("root_exit_code")
                    if result.get("program_status") in {"FAIL", "TIMED_OUT"} or (type(exit_code) is int and exit_code != 0):
                        entry["status"] = "failed"
                        if type(exit_code) is int:
                            entry["detail"] += " · 退出码 " + str(exit_code)
    return sorted(entries.values(), key=lambda entry: entry["order"])


def activity_summary(task, entries):
    active = [entry for entry in entries if entry["status"] == "running"]
    return {"task_id": task["task_id"], "revision": task["task_revision"], "total": len(entries),
            "current": active[-1] if active else None, "recent": entries[-3:],
            "active_count": len(active), "problem_notice": _activity_problem_notice(task, entries)}


def activity_page(entries, before=None, limit=50):
    selected = [entry for entry in entries if before is None or entry["order"] < before]
    page = selected[-limit:]
    return {"entries": list(reversed(page)), "total": len(entries),
            "next_before": page[0]["order"] if len(selected) > len(page) and page else None}
